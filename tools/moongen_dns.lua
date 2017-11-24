local mg     = require "moongen"
local memory = require "memory"
local device = require "device"
local ts     = require "timestamping"
local filter = require "filter"
local hist   = require "histogram"
local stats  = require "stats"
local timer  = require "timer"
local arp    = require "proto.arp"
local log    = require "log"

-- set addresses here
local DST_MAC	= "00:1b:21:bc:ab:b0"
local SRC_MAC	= "00:1b:21:bc:ab:80"
local SRC_IP_BASE	= "10.0.0.10" -- actual address will be SRC_IP_BASE + random(0, flows)
local DST_IP_BASE	= "10.110.0.0" -- actual address will be SRC_IP_BASE + random(0, flows)
local DST_IP		= "10.1.0.10"
local SRC_PORT		= 1234
local DST_PORT		= 19899


function configure(parser)
	parser:description("Generates UDP traffic and measure latencies. Edit the source to modify constants like IPs.")
  parser:argument("dev", "Devices to use."):args("+"):convert(tonumber)
	parser:option("-t --threads", "Number of threads per device."):args(1):convert(tonumber):default(1)
	parser:option("-r --rate", "Transmit rate in Mbit/s."):default(10000):convert(tonumber)
	parser:option("-f --flows", "Number of flows (randomized source IP)."):default(4):convert(tonumber)
	parser:option("-s --size", "Packet size."):default(100):convert(tonumber)
end

function master(args)
  for i, dev in ipairs(args.dev) do
		-- arp needs extra queues
		local dev = device.config{
			port = dev,
			txQueues = args.threads,
			rxQueues = 1
		}
		args.dev[i] = dev
	end
	device.waitForLinks()
	-- max 1kpps timestamping traffic timestamping
	-- rate will be somewhat off for high-latency links at low rates
	-- if args.rate > 0 then
	-- 	txDev:getTxQueue(0):setRate(args.rate - (args.size + 4) * 8 / 1000)
	-- end

  -- configure tx rates and start transmit slaves
	for i, dev in ipairs(args.dev) do
		for i = 1, args.threads do
			local queue = dev:getTxQueue(i - 1)
			if args.rate then
				queue:setRate(args.rate / args.threads)
			end
      mg.startTask("loadSlave", queue, dev, args.size, args.flows)
		end
	end
	-- mg.startTask("timerSlave", txDev:getTxQueue(1),
  --              rxDev:getRxQueue(1), args.size, args.flows)
	mg.waitForTasks()
end


local DNS_TYPE_A	= 1
local DNS_TYPE_NS	= 2
local DNS_TYPE_CNAME	= 5
local DNS_TYPE_SOA	= 6
local DNS_TYPE_PTR	= 12
local DNS_TYPE_MX	= 15
local DNS_TYPE_TXT	= 16
local DNS_TYPE_AAAA	= 28
local DNS_TYPE_SRV	= 33
local DNS_TYPE_OPT	= 41

local function pack_dns_query(xid, name, type)
  flag = 0x0100   -- flag with RD set

  local packed = pack(">HHHHHHsHH", xid, flag, 1, 0, 0, 0, name, type, 1)
end

local function pack(format, ...)
  local stream = {}
  local vars = {...}
  local endianness = true

  for i = 1, format:len() do
    local opt = format:sub(i, i)

    if opt == '<' then
      endianness = true
    elseif opt == '>' then
      endianness = false
    elseif opt:find('[bBhHiIlL]') then
      local n = opt:find('[hH]') and 2 or opt:find('[iI]') and 4 or opt:find('[lL]') and 8 or 1
      local val = tonumber(table.remove(vars, 1))

      local bytes = {}
      for j = 1, n do
        table.insert(bytes, string.char(val % (2 ^ 8)))
        val = math.floor(val / (2 ^ 8))
      end

      if not endianness then
        table.insert(stream, string.reverse(table.concat(bytes)))
      else
        table.insert(stream, table.concat(bytes))
      end
    elseif opt:find('[fd]') then
      local val = tonumber(table.remove(vars, 1))
      local sign = 0

      if val < 0 then
        sign = 1
        val = -val
      end

      local mantissa, exponent = math.frexp(val)
      if val == 0 then
        mantissa = 0
        exponent = 0
      else
        mantissa = (mantissa * 2 - 1) * math.ldexp(0.5, (opt == 'd') and 53 or 24)
        exponent = exponent + ((opt == 'd') and 1022 or 126)
      end

      local bytes = {}
      if opt == 'd' then
        val = mantissa
        for i = 1, 6 do
          table.insert(bytes, string.char(math.floor(val) % (2 ^ 8)))
          val = math.floor(val / (2 ^ 8))
        end
      else
        table.insert(bytes, string.char(math.floor(mantissa) % (2 ^ 8)))
        val = math.floor(mantissa / (2 ^ 8))
        table.insert(bytes, string.char(math.floor(val) % (2 ^ 8)))
        val = math.floor(val / (2 ^ 8))
      end

      table.insert(bytes, string.char(math.floor(exponent * ((opt == 'd') and 16 or 128) + val) % (2 ^ 8)))
      val = math.floor((exponent * ((opt == 'd') and 16 or 128) + val) / (2 ^ 8))
      table.insert(bytes, string.char(math.floor(sign * 128 + val) % (2 ^ 8)))
      val = math.floor((sign * 128 + val) / (2 ^ 8))

      if not endianness then
        table.insert(stream, string.reverse(table.concat(bytes)))
      else
        table.insert(stream, table.concat(bytes))
      end
    elseif opt == 's' then
      table.insert(stream, tostring(table.remove(vars, 1)))
      table.insert(stream, string.char(0))
    elseif opt == 'c' then
      local n = format:sub(i + 1):match('%d+')
      local length = tonumber(n)

      if length > 0 then
        local str = tostring(table.remove(vars, 1))
        if length - str:len() > 0 then
          str = str .. string.rep(' ', length - str:len())
        end
        table.insert(stream, str:sub(1, length))
      end
      i = i + n:len()
    end
  end

  return table.concat(stream)
end


local function fillDnsPacket(buf, len)
  local lenlabel = "\4www1\7example\3com\0"
  local query = lenlabel .. pack(">HH", DNS_TYPE_A, 1)
  -- size = 14+20+8+12+string.len(query)

	buf:getDns4Packet():fill{
		-- ethSrc = queue,
		ethSrc = SRC_MAC,
		ethDst = DST_MAC,
		-- ip4Src = SRC_IP,
		-- ip4Dst = DST_IP,
		udpSrc = SRC_PORT,
		udpDst = DST_PORT,
    -- dnsId = 0,
    dnsRecDesired = 1,
    dnsQDCount = 1,
    dnsMessageContent = query,
		pktLength = len
	}
end

function loadSlave(queue, rxDev, size, flows)
	local mempool = memory.createMemPool(function(buf)
		fillDnsPacket(buf, size)
	end)
	local bufs = mempool:bufArray()
	local counter = 0
	local txCtr = stats:newDevTxCounter(queue, "plain")
	local rxCtr = stats:newDevRxCounter(rxDev, "plain")
	local srcBaseIP = parseIPAddress(SRC_IP_BASE)
	local dstBaseIP = parseIPAddress(DST_IP_BASE)
  local lenlabel = "\4www1\7example\3com\0"
  local query = lenlabel .. pack(">HH", DNS_TYPE_A, 1)

	while mg.running() do
		bufs:alloc(size)
		for i, buf in ipairs(bufs) do
			local pkt = buf:getDns4Packet()
			pkt.ip4.src:set(srcBaseIP + counter)
			pkt.ip4.dst:set(dstBaseIP + counter)
      pkt.udp.src = pkt.udp.src + counter
      -- pkt.dns.body:set()
			counter = incAndWrap(counter, flows)
		end
		-- UDP checksums are optional, so using just IPv4 checksums would be sufficient here
		bufs:offloadUdpChecksums()
		queue:send(bufs)
		txCtr:update()
		rxCtr:update()
	end
	txCtr:finalize()
	rxCtr:finalize()
end

-- function timerSlave(txQueue, rxQueue, size, flows)
-- 	if size < 84 then
-- 		log:warn("Packet size %d is smaller than minimum timestamp size 84. Timestamped packets will be larger than load packets.", size)
-- 		size = 84
-- 	end
-- 	local timestamper = ts:newUdpTimestamper(txQueue, rxQueue)
-- 	local hist = hist:new()
-- 	mg.sleepMillis(1000) -- ensure that the load task is running
-- 	local counter = 0
-- 	local rateLimit = timer:new(0.001)
-- 	local baseIP = parseIPAddress(SRC_IP_BASE)
-- 	while mg.running() do
-- 		hist:update(timestamper:measureLatency(size, function(buf)
-- 			fillDnsPacket(buf, size)
-- 			local pkt = buf:getDns4Packet()
-- 			pkt.ip4.src:set(baseIP + counter)
-- 			counter = incAndWrap(counter, flows)
-- 		end))
-- 		rateLimit:wait()
-- 		rateLimit:reset()
-- 	end
-- 	-- print the latency stats after all the other stuff
-- 	mg.sleepMillis(300)
-- 	hist:print()
-- 	hist:save("histogram.csv")
-- end
