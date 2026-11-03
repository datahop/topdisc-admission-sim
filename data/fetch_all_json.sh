#!/bin/sh
# Honest advertiser IPs: the discv4 DNS-list crawl (all.json) as of 2026-08-19,
# the day the original report was written. The file was later removed from the
# repository's master branch, so it is fetched at a fixed commit.
set -e
cd "$(dirname "$0")"
curl -fsSL -o all.json https://raw.githubusercontent.com/ethereum/discv4-dns-lists/cd922767663ed4e809adc52bddc5a0d74aaa7e78/all.json
echo "all.json: $(wc -c < all.json) bytes"
