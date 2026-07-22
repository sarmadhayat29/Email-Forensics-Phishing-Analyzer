import unittest
import os
import sys
import shutil

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../src')))

from main import AnalyzerPipeline


class TestAnalyzerPipeline(unittest.TestCase):
    def setUp(self):
        self.output_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../test_reports'))
        self.input_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../samples'))
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def tearDown(self):
        if os.path.exists(self.output_dir):
            shutil.rmtree(self.output_dir)

    def test_run_pipeline(self):
        pipeline = AnalyzerPipeline(output_dir=self.output_dir)
        pipeline.run(self.input_dir)
        
        # Verify files were created
        self.assertTrue(os.path.exists(os.path.join(self.output_dir, "summary.json")))
        self.assertTrue(os.path.exists(os.path.join(self.output_dir, "legit_sample_1.report.html")))
        self.assertTrue(os.path.exists(os.path.join(self.output_dir, "legit_sample_1.report.json")))
        self.assertTrue(os.path.exists(os.path.join(self.output_dir, "phishing_sample_1.report.html")))
        self.assertTrue(os.path.exists(os.path.join(self.output_dir, "phishing_sample_1.report.json")))

if __name__ == '__main__':
    unittest.main()
