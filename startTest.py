n = int(input())
a = list(map(int, input().split()))[:n]

even_pos = [a[i] for i in range(1, n, 2)]

even_pos.sort(reverse=True)

res = []
idx_even = 0
for i in range(n):
    if i % 2 == 1:      
        res.append(str(even_pos[idx_even]))
        idx_even += 1
    else:
        res.append(str(a[i]))

print(*res)