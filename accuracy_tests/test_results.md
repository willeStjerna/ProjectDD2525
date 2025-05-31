# Accuracy Test Results

## Test Categories

### True Positives (Should be detected)
- [ ] tp1_system_command.py - System command execution
- [ ] tp2_data_exfiltration.py - Network data exfiltration  
- [ ] tp3_hex_backdoor.py - Hex encoded backdoor
- [ ] tp4_file_deletion.py - File deletion with eval
- [ ] tp5_crypto_miner.py - Cryptocurrency miner

**Expected: 5 detections | Actual: ___ detections**

### True Negatives (Should NOT be detected)
- [ ] tn1_config_storage.py - Legitimate config storage
- [ ] tn2_image_data.py - Image data in Base64
- [ ] tn3_hex_identifiers.py - Hex color codes
- [ ] tn4_url_encoding.py - Legitimate URL encoding
- [ ] tn5_crypto_operations.py - Password hashing

**Expected: 0 detections | Actual: ___ detections**

### False Positive Risks (Legitimate code that might be flagged)
- [ ] fpr1_system_admin.py - System administration tool
- [ ] fpr2_dev_tools.py - Development API tester
- [ ] fpr3_file_processor.py - File processing utility

**Expected: 0-1 detections | Actual: ___ detections**

### False Negative Risks (Sophisticated attacks that might evade)
- [ ] fnr1_double_encoded.py - Double-encoded payload
- [ ] fnr2_split_payload.py - Split payload across variables
- [ ] fnr3_custom_encoding.py - Custom XOR encoding
- [ ] fnr4_steganography.py - Hidden in comments
- [ ] fnr5_delayed_execution.py - Time-delayed execution

**Expected: 2-5 detections | Actual: ___ detections**

## Accuracy Metrics

- **True Positive Rate**: ___/5 = ___%
- **True Negative Rate**: ___/5 = ___%  
- **False Positive Rate**: ___/3 = ___%
- **False Negative Rate**: ___/5 = ___%

## Overall Accuracy: ___% 

## Notes:
- List any unexpected results
- Areas for improvement
- Patterns that need adjustment
