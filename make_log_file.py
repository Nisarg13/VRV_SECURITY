with open('data.txt', 'r') as input_file:
    with open('sample.log', 'w') as log_file:
        for line in input_file:
            log_file.write(line)
