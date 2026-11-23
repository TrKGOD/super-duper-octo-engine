import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from scripts.run_benchmark import run

class BenchmarkRunnerTests(unittest.TestCase):
    def test_runner_invokes_cli_and_emits_schema_valid_prediction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            cases=root/'cases'; cases.mkdir()
            (cases/'one.json').write_text(json.dumps({'case_id':'SYN-TEST-001','kind':'synthetic','description':'Fixture with a demonstrated cross-user object read.','expected_finding':True,'required_evidence':['request_identity'],'fixtures':{'request_identity':'user-b','object_owner_identity':'user-a','authorization_decision':'missing'}}),encoding='utf-8')
            fake=root/'claude-fake'
            fake.write_text('#!'+sys.executable+'\nimport json\nprint(json.dumps({"case_id":"SYN-TEST-001","detected":True,"vulnerability_type":"BOLA","evidence_fields":["request_identity"]}))\n',encoding='utf-8')
            fake.chmod(0o755)
            predictions,manifest=run(cases,'vulnerability-agent','pinned-model',60,'synthetic-lab-v1',str(fake))
            self.assertEqual(predictions['predictions'][0]['case_id'],'SYN-TEST-001')
            self.assertEqual(manifest['execution'],'claude_code_cli_agent_prompt')
            self.assertEqual(manifest['model'],'pinned-model')

if __name__=='__main__': unittest.main()
