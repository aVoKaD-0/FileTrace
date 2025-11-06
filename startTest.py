n = int(input())
a = list(map(int, input().split()))[:n]

# собираем элементы с чётных позиций (позиции считаются с 1)
even_pos = [a[i] for i in range(1, n, 2)]

# сортируем по убыванию
even_pos.sort(reverse=True)

# собираем результат
res = []
idx_even = 0
for i in range(n):
    if i % 2 == 1:          # индекс i=1 соответствует позиции 2 (чётная)
        res.append(str(even_pos[idx_even]))
        idx_even += 1
    else:
        res.append(str(a[i]))

print(*res)