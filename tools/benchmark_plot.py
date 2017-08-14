from os import path
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator

import numpy as np

STATIC_DIR = path.join(path.dirname(path.dirname(path.realpath(__file__))),
                       "doc", "static")

fig1 = plt.figure()
ax = fig1.add_subplot(111)

# one port 50 bytes
x = [1, 2, 3, 4, 5]
y_1_port_small = [2.86, 5.52, 7.61, 10.16, 12.43]
y_1_port_big = [2.41, 5.16, 6.59, 9.30, 11.39]

ax.plot(x, y_1_port_small, 'r-o', markersize=5, label="response size(50 bytes)")
ax.plot(x, y_1_port_big, 'b-o', markersize=5, label="response size(66 bytes)")

for i, j in zip(x, y_1_port_small):
    ax.annotate(str(j)+"M", xy=(i, j), xytext=(2, 10), textcoords='offset points')

for i, j in zip(x, y_1_port_big):
    ax.annotate(str(j)+"M", xy=(i, j), xytext=(2, -10), textcoords='offset points')

ax.set_xlabel('CPU physical cores')
ax.set_ylabel('QPS(million)')
ax.set_title('Benchmark (one 10G port)')
ax.grid(True)
ax.xaxis.set_major_locator(MaxNLocator(integer=True))
ax.legend(loc=2)

fig1.savefig(path.join(STATIC_DIR, "benchmark_1_port.png"))

# two port 66 bytes
x_2_port = [1, 2, 3, 4, 5, 6, 7, 8]
# currate
y_2_port_big = [2.60, 5.16, 7.01, 8.96, 11.41, 13.17, 14.88, 16.37]
# inaccurate, need do brenchmark for small packet(50 bytes)
y_2_port_small = [2.85, 5.64, 7.80, 10.13, 12.45, 14.68, 16.52, 18.26]

fig2 = plt.figure()
ax2 = fig2.add_subplot(111)

ax2.grid(True)

ax2.plot(x_2_port, y_2_port_small, "r-o", markersize=5,
         label="response size(50 bytes)")
ax2.plot(x_2_port, y_2_port_big, "b-o", label="response size(66 bytes)")

for i, j in zip(x_2_port, y_2_port_small):
    ax2.annotate(str(j)+"M", xy=(i, j), xytext=(2, 10), textcoords='offset points')

for i, j in zip(x_2_port, y_2_port_big):
    ax2.annotate(str(j)+"M", xy=(i, j), xytext=(2, -10), textcoords='offset points')
# colormap = plt.cm.gist_ncar #nipy_spectral, Set1,Paired
# colors = [colormap(i) for i in np.linspace(0, 1,len(ax2.lines))]
# for i, j in enumerate(ax2.lines):
#     j.set_color(colors[i])

ax2.set_xlabel('CPU physical cores')
ax2.set_ylabel('QPS(million)')
ax2.set_title('Benchmark (two 10G port)')
ax2.grid(True)
ax2.legend(loc=2)
fig2.savefig(path.join(STATIC_DIR, "benchmark_2_port.png"))

plt.show()
