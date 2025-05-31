#!/usr/bin/env python3
"""
Test runner to evaluate detector accuracy and generate metrics
"""

import os
import subprocess
import json
from pathlib import Path

class AccuracyEvaluator:
    """Evaluate detector accuracy across different test categories"""
    
    def __init__(self, detector_script="detector.py"):
        self.detector_script = detector_script
        self.results = {
            'true_positives': {},
            'true_negatives': {},
            'false_positive_risks': {},
            'false_negative_risks': {}
        }
    
    def run_all_tests(self):
        """Run detector on all test categories"""
        test_dir = Path("accuracy_tests")
        
        if not test_dir.exists():
            print("Error: accuracy_tests directory not found. Run the test suite generator first.")
            return
        
        print("Running accuracy tests...")
        print("=" * 50)
        
        # Test each category
        for category in self.results.keys():
            category_dir = test_dir / category
            if category_dir.exists():
                print(f"\nTesting {category.replace('_', ' ').title()}:")
                self.test_category(category_dir, category)
        
        # Generate report
        self.generate_accuracy_report()
    
    def test_category(self, category_dir, category_name):
        """Test all files in a category"""
        for file_path in category_dir.glob("*.py"):
            print(f"  Testing {file_path.name}...", end=" ")
            
            try:
                # Run detector on file
                result = subprocess.run([
                    'python', self.detector_script, str(file_path)
                ], capture_output=True, text=True, timeout=30)
                
                # Count detections
                detections = self.count_detections(result.stdout)
                self.results[category_name][file_path.name] = {
                    'detections': detections,
                    'output': result.stdout
                }
                
                print(f"{detections} detections")
                
            except subprocess.TimeoutExpired:
                print("TIMEOUT")
                self.results[category_name][file_path.name] = {
                    'detections': -1,
                    'output': "Timeout"
                }
            except Exception as e:
                print(f"ERROR: {e}")
                self.results[category_name][file_path.name] = {
                    'detections': -1,
                    'output': f"Error: {e}"
                }
    
    def count_detections(self, output):
        """Count number of detections in detector output"""
        if "No suspicious encoded content detected" in output:
            return 0
        
        # Count "Detection #" occurrences
        import re
        matches = re.findall(r'Detection #\d+', output)
        return len(matches)
    
    def generate_accuracy_report(self):
        """Generate comprehensive accuracy report"""
        print("\n" + "=" * 60)
        print("ACCURACY EVALUATION REPORT")
        print("=" * 60)
        
        # Expected results for each category
        expected = {
            'true_positives': {'should_detect': True, 'files': 5},
            'true_negatives': {'should_detect': False, 'files': 5},
            'false_positive_risks': {'should_detect': False, 'files': 3},
            'false_negative_risks': {'should_detect': True, 'files': 5}
        }
        
        total_correct = 0
        total_tests = 0
        
        for category, expectations in expected.items():
            print(f"\n{category.replace('_', ' ').title()}:")
            print("-" * 40)
            
            correct_predictions = 0
            category_tests = 0
            
            for filename, result in self.results[category].items():
                detections = result['detections']
                
                if detections == -1:  # Error or timeout
                    print(f"  {filename}: ERROR/TIMEOUT")
                    continue
                
                category_tests += 1
                total_tests += 1
                
                # Determine if prediction was correct
                detected = detections > 0
                should_detect = expectations['should_detect']
                
                is_correct = detected == should_detect
                if is_correct:
                    correct_predictions += 1
                    total_correct += 1
                
                status = "✓" if is_correct else "✗"
                print(f"  {filename}: {detections} detections {status}")
            
            # Category accuracy
            if category_tests > 0:
                accuracy = (correct_predictions / category_tests) * 100
                print(f"  Category Accuracy: {correct_predictions}/{category_tests} ({accuracy:.1f}%)")
        
        # Overall metrics
        print(f"\n{'='*60}")
        print("OVERALL METRICS:")
        print(f"{'='*60}")
        
        if total_tests > 0:
            overall_accuracy = (total_correct / total_tests) * 100
            print(f"Overall Accuracy: {total_correct}/{total_tests} ({overall_accuracy:.1f}%)")
        
        # Specific metrics
        self.calculate_specific_metrics()
        
        # Save detailed results
        self.save_detailed_results()
    
    def calculate_specific_metrics(self):
        """Calculate specific accuracy metrics"""
        
        # True Positives: Malicious files correctly identified
        tp_correct = sum(1 for result in self.results['true_positives'].values() 
                        if result['detections'] > 0)
        tp_total = len(self.results['true_positives'])
        
        # True Negatives: Benign files correctly identified as safe
        tn_correct = sum(1 for result in self.results['true_negatives'].values() 
                        if result['detections'] == 0)
        tn_total = len(self.results['true_negatives'])
        
        # False Positives: Benign files incorrectly flagged
        fp_count = sum(1 for result in self.results['true_negatives'].values() 
                      if result['detections'] > 0)
        fp_count += sum(1 for result in self.results['false_positive_risks'].values() 
                       if result['detections'] > 0)
        
        # False Negatives: Malicious files missed
        fn_count = sum(1 for result in self.results['true_positives'].values() 
                      if result['detections'] == 0)
        fn_count += sum(1 for result in self.results['false_negative_risks'].values() 
                       if result['detections'] == 0)
        
        print(f"\nDetailed Metrics:")
        print(f"  True Positive Rate: {tp_correct}/{tp_total} ({(tp_correct/tp_total*100):.1f}%)")
        print(f"  True Negative Rate: {tn_correct}/{tn_total} ({(tn_correct/tn_total*100):.1f}%)")
        print(f"  False Positives: {fp_count}")
        print(f"  False Negatives: {fn_count}")
        
        # Calculate precision and recall if possible
        total_predicted_positive = tp_correct + fp_count
        if total_predicted_positive > 0:
            precision = tp_correct / total_predicted_positive
            print(f"  Precision: {precision:.3f}")
        
        total_actual_positive = tp_correct + fn_count
        if total_actual_positive > 0:
            recall = tp_correct / total_actual_positive
            print(f"  Recall: {recall:.3f}")
        
        return {
            'tp_rate': tp_correct/tp_total if tp_total > 0 else 0,
            'tn_rate': tn_correct/tn_total if tn_total > 0 else 0,
            'false_positives': fp_count,
            'false_negatives': fn_count
        }
    
    def save_detailed_results(self):
        """Save detailed results to JSON file"""
        with open("accuracy_test_results.json", "w") as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\nDetailed results saved to: accuracy_test_results.json")
    
    def show_false_positives(self):
        """Show details of false positive cases"""
        print(f"\n{'='*60}")
        print("FALSE POSITIVE ANALYSIS:")
        print(f"{'='*60}")
        
        # Check true negatives that were flagged
        for filename, result in self.results['true_negatives'].items():
            if result['detections'] > 0:
                print(f"\nFALSE POSITIVE: {filename}")
                print(f"Detections: {result['detections']}")
                print("Output preview:")
                print(result['output'][:300] + "..." if len(result['output']) > 300 else result['output'])
        
        # Check false positive risks that were flagged
        for filename, result in self.results['false_positive_risks'].items():
            if result['detections'] > 0:
                print(f"\nFALSE POSITIVE RISK: {filename}")
                print(f"Detections: {result['detections']}")
                print("Output preview:")
                print(result['output'][:300] + "..." if len(result['output']) > 300 else result['output'])
    
    def show_false_negatives(self):
        """Show details of false negative cases"""
        print(f"\n{'='*60}")
        print("FALSE NEGATIVE ANALYSIS:")
        print(f"{'='*60}")
        
        # Check true positives that were missed
        for filename, result in self.results['true_positives'].items():
            if result['detections'] == 0:
                print(f"\nFALSE NEGATIVE: {filename}")
                print("This malicious file was NOT detected!")
        
        # Check false negative risks that were missed
        for filename, result in self.results['false_negative_risks'].items():
            if result['detections'] == 0:
                print(f"\nFALSE NEGATIVE RISK: {filename}")
                print("This sophisticated attack was NOT detected!")

def main():
    """Main function to run accuracy tests"""
    import sys
    
    detector_script = sys.argv[1] if len(sys.argv) > 1 else "detector.py"
    
    if not os.path.exists(detector_script):
        print(f"Error: Detector script '{detector_script}' not found")
        print("Usage: python accuracy_test_runner.py [detector_script.py]")
        return
    
    evaluator = AccuracyEvaluator(detector_script)
    evaluator.run_all_tests()
    
    # Show detailed analysis
    print("\nWould you like to see detailed false positive/negative analysis? (y/n)")
    if input().lower().startswith('y'):
        evaluator.show_false_positives()
        evaluator.show_false_negatives()

if __name__ == "__main__":
    main()