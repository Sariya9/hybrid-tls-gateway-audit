import unittest
from observation_analysis import analyse, confusion


class ObservationTests(unittest.TestCase):
    def test_equal_projection_opposite_labels_requires_error(self):
        rows = [dict(request_id=str(i), classification=label, path='/restricted', required_mask=3,
                     front_group='H', http_status=200, observed_mask=mask, case_id='A',
                     allowed_under_declared_requirement=True, origin='restricted')
                for i, (label, mask) in enumerate([('admitted_conforming', 3), ('admitted_violation', 1)])]
        summary = dict(cases=[dict(requests=rows, policy='test')], totals=dict(requests=3))
        clients = [dict(request_id=str(i), client=dict(tls_version='TLSv1.3', certificate_verified=True,
                                                      peer_certificate_sha256='ab' * 32)) for i in range(2)]
        result = analyse(summary, dict(scenarios=[dict(id='A', requests=clients,
                         specification=dict(client_mode='H', restricted_origin='H'))]))
        self.assertEqual(result['minimum_binary_errors'], 1)
        self.assertEqual(result['mixed_classes'], 1)
        self.assertEqual(result['excluded_refusals'], 1)
        self.assertEqual(result['baselines']['declared_front_only']['false_compliance'], 1)

    def test_excessive_refusal_needs_a_positive_control(self):
        row = dict(request_id='r', case_id='A', classification='rejected_available', path='/compat')
        summary = dict(cases=[dict(requests=[row])])
        record = dict(scenarios=[dict(id='A', requests=[dict(request_id='r', client={})],
                                     specification=dict(client_mode='H', restricted_origin='H'))])
        with self.assertRaisesRegex(ValueError, 'lacks a matched'):
            analyse(summary, record)

    def test_declaration_separates_same_groups(self):
        rows = [dict(classification=label, required_mask=mask, observed_mask=1)
                for label, mask in [('admitted_conforming', 0), ('admitted_violation', 3)]]
        checked = confusion(rows, lambda r: r['observed_mask'] & r['required_mask'] == r['required_mask'])
        self.assertEqual(checked, dict(correct_compliance=1, false_compliance=0,
                                      false_violation=0, correct_violation=1))

    def test_all_negative_rule_misclassifies_conforming_admission(self):
        rows = [dict(classification='admitted_conforming'), dict(classification='admitted_violation')]
        result = confusion(rows, lambda r: False)
        self.assertEqual(result['false_violation'], 1)
        self.assertEqual(result['correct_violation'], 1)


if __name__ == '__main__':
    unittest.main()
