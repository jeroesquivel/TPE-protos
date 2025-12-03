#!/bin/bash

echo "=== Test DNS no bloqueante ==="
echo ""

rm -f /tmp/test_*.log

(
  echo "[$(date +%H:%M:%S.%N)] Iniciando conexión 1 (wikipedia.org)"
  time curl --max-time 30 --proxy socks5h://user:pass@localhost:1080 http://wikipedia.org > /dev/null 2>&1
  echo "[$(date +%H:%M:%S.%N)] Conexión 1 terminada"
) > /tmp/test_1.log 2>&1 &

PID1=$!

sleep 0.5

(
  echo "[$(date +%H:%M:%S.%N)] Iniciando conexión 2 (google.com)"
  time curl --max-time 30 --proxy socks5h://user:pass@localhost:1080 http://google.com > /dev/null 2>&1
  echo "[$(date +%H:%M:%S.%N)] Conexión 2 terminada"
) > /tmp/test_2.log 2>&1 &

PID2=$!

echo "Esperando a que terminen ambas conexiones..."
wait $PID1
wait $PID2

echo ""
echo "=== Resultados ==="
echo ""
echo "--- Conexión 1 (wikipedia.org) ---"
cat /tmp/test_1.log
echo ""
echo "--- Conexión 2 (google.com) ---"
cat /tmp/test_2.log
echo ""
rm -f /tmp/test_*.log