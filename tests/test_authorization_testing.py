import unittest

from core.authorization_testing import compare_function_access, compare_object_access


class AuthorizationComparisonTests(unittest.TestCase):
    def test_matching_owner_and_non_owner_object_response_is_candidate_only(self):
        owner = {"status_code": 200, "response_excerpt": '{"id":"synthetic-1","owner":"user-a","name":"demo"}', "evidence_refs": ["ev-a"]}
        other = {"status_code": 200, "response_excerpt": '{"name":"demo","owner":"user-a","id":"synthetic-1"}', "evidence_refs": ["ev-b"]}
        result = compare_object_access(
            owner, other, owner_identity="user-a", other_identity="user-b",
            object_reference="synthetic-object-1",
        )
        self.assertEqual(result["classification"], "potential_bola_same_object_representation")
        self.assertEqual(result["status"], "candidate_only")
        self.assertEqual(result["evidence_refs"], ["ev-a", "ev-b"])

    def test_volatile_json_fields_do_not_hide_same_object_representation(self):
        owner = {"status_code": 200, "response_excerpt": '{"id":"1","updatedAt":"now","requestId":"a"}'}
        other = {"status_code": 200, "response_excerpt": '{"requestId":"b","updatedAt":"later","id":"1"}'}
        result = compare_object_access(
            owner, other, owner_identity="a", other_identity="b", object_reference="object-1"
        )
        self.assertTrue(result["same_normalized_representation"])

    def test_truncated_response_is_inconclusive(self):
        owner = {"status_code": 200, "response_excerpt": '{"id":"1"}', "response_body_truncated": True}
        other = {"status_code": 200, "response_excerpt": '{"id":"1"}'}
        result = compare_object_access(
            owner, other, owner_identity="a", other_identity="b", object_reference="object-1"
        )
        self.assertEqual(result["classification"], "inconclusive_truncated_response")

    def test_denial_is_an_observation_not_a_proof_of_complete_authorization(self):
        owner = {"status_code": 200, "response_excerpt": '{"id":"1"}'}
        other = {"status_code": 403, "response_excerpt": ""}
        result = compare_object_access(
            owner, other, owner_identity="a", other_identity="b", object_reference="object-1"
        )
        self.assertEqual(result["classification"], "access_denial_observed")
        self.assertEqual(result["status"], "observation")

    def test_same_identity_is_rejected(self):
        with self.assertRaises(ValueError):
            compare_object_access(
                {"status_code": 200}, {"status_code": 200},
                owner_identity="a", other_identity="a", object_reference="object-1"
            )

    def test_function_level_success_is_candidate_only(self):
        result = compare_function_access(
            {"status_code": 200, "evidence_refs": ["ev-admin"]},
            {"status_code": 200, "evidence_refs": ["ev-user"]},
            baseline_role="admin", comparison_role="user",
            function_reference="GET /api/admin/reports",
        )
        self.assertEqual(result["classification"], "potential_function_level_authorization_gap")
        self.assertEqual(result["status"], "candidate_only")


if __name__ == "__main__":
    unittest.main()
