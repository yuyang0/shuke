import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator

import numpy as np

ax = plt.subplot(111)

x = [1, 2, 3, 4, 5]
y = [2.86, 5.52, 7.61, 10.16, 12.43]

plt.plot(x, y, 'r-+', markersize=10, markeredgewidth=2, lw=2)
for i, j in zip(x, y):
    ax.annotate(str(j)+"M", xy=(i,j), xytext=(2,10), textcoords='offset points')

plt.xlabel('CPU pysical cores')
plt.ylabel('QPS(million)')
plt.title('Benchmark (one 10G port)')
plt.grid(True)
ax.xaxis.set_major_locator(MaxNLocator(integer=True))

plt.savefig("benchmark_1_port.png")
plt.show()
