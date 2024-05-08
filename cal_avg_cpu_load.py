def calculate_average(filename):
    total = 0
    count = 0

    with open(filename, 'r') as file:
        for line in file:
            percent = float(line.strip()[:-1])
            if percent >= 10:
                total += percent
                count += 1

    if count == 0:
        print("No non-zero percent numbers found in the file.")
        return None
    else:
        average = total / count
        return average

# Change 'filename.txt' to the path of your text file
filename = 'n_UQ.txt'
average = calculate_average(filename)
if average is not None:
    print("Average of non-zero percent numbers:", average)
