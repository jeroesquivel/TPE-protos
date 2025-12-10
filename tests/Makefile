CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -O2 -pthread
LDFLAGS = -pthread -lm

TESTS = test_max_connections test_throughput test_latency

.PHONY: all clean

all: $(TESTS)

test_max_connections: test_max_connections.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_throughput: test_throughput.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_latency: test_latency.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)


clean:
	rm -f $(TESTS) *.csv *.log
	rm -f throughput_results.csv latency_results.csv

help:
	@echo "Tests de Estrés disponibles:"
	@echo "  make all                  - Compila todos los tests"
	@echo "  make test_max_connections - Compila test de máx. conexiones"
	@echo "  make test_throughput      - Compila test de throughput"
	@echo "  make test_latency         - Compila test de latencia"
	@echo "  make clean                - Limpia binarios y resultados"
	@echo ""
	@echo "Uso:"
	@echo "  ./test_max_connections [username] [password]"
	@echo "  ./test_throughput [username] [password]"
	@echo "  ./test_latency [username] [password]"