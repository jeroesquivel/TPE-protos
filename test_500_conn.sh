#!/bin/bash

echo "=== Test 500 conexiones==="

SUCCESS=0
FAILED=0

for i in {1..500}; do
  (
    if curl --max-time 10 --proxy socks5h://user:pass@localhost:1080 http://google.com > /dev/null 2>&1; then
      echo "✓ $i"
    else
      echo "✗ $i"
    fi
  ) &
  
  #delay cada 50 para no saturar la shell
  if [ $((i % 50)) -eq 0 ]; then
    sleep 0.1
  fi
done

echo "Esperando a que todas terminen..."
wait

echo ""
echo "=== Verificando métricas ==="
python3 admin_client.py metrics
