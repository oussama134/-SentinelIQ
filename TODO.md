# SentinelIQ LSTM Fix — TODO

## Root Cause
- `_ml_pending_df` and `_ml_pending_metadata` in `main.py` still accumulate flows across all pcaps
- LSTM processes 112k+ flows at once → blocks backend for 20+ minutes → forwarder timeouts
- DDoS threshold too high (0.70) → hping3 not detected

## Steps

- [x] **Step 0:** Analyze root cause (buffer accumulation not fixed)
- [x] **Step 1:** Remove `_ml_pending_df` and `_ml_pending_metadata` globals from `main.py`
- [x] **Step 2:** Rewrite `_process_pcap()` in `main.py` — process each pcap independently, add 5000-flow safety limit
- [x] **Step 3:** Lower `CLASS_THRESHOLDS["DDoS"]` from 0.70 → 0.55 in `correlation.py`
- [ ] **Step 4:** Restart uvicorn and verify fix
