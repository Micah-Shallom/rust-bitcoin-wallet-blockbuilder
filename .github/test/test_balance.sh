result=$(OPENSSL_CONF=./.github/test/openssl.cnf bash ./solution/run_balance.sh | tail -n 1)
echo $result
grep -xq "$result" ./.github/test/wallet_balances.txt && echo "PASS" || echo "FAIL"
