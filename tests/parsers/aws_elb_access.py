#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Tests for the Apache access log parser."""

import unittest

from plaso.parsers import aws_elb_access
from tests.parsers import test_lib
import logging


class AWSELBUnitTest(test_lib.ParserTestCase):
  """Tests for an AWS ELB access log parser."""

  def testParse(self):
    """Tests the Parse function."""
    parser = aws_elb_access.AWSELBParser()
    storage_writer = self._ParseFile(['aws_elb_access.log'], parser)

    # Test number of events and warnings
    number_of_events = storage_writer.GetNumberOfAttributeContainers('event')
    self.assertEqual(number_of_events, 24)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'extraction_warning')
    self.assertEqual(number_of_warnings, 0)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'recovery_warning')
    self.assertEqual(number_of_warnings, 0)

    # The order in which parser generates events is nondeterministic hence
    # we sort the events.
    events = list(storage_writer.GetSortedEvents())

    expected_event_values = {
        'actions_executed': 'waf,forward',
        'chosen_cert_arn': 'arn:aws:abc:us-east-2:234567891234:certificate',
        'classification': '-',
        'classification_reason': '-',
        'source_ip_address': '192.168.1.10',
        'source_port': 44325,
        'data_type': 'aws:elb:access',
        'domain_name': 'www.domain.name',
        'resource_identifier': 'app/production-web/jf29fj2198ejf922',
        'elb_status_code': 200,
        'error_reason': '-',
        'matched_rule_priority': 2,
        'received_bytes': 391,
        'redirect_url': '-',
        'request': 'GET https://www.domain.name:443/ HTTP/1.1',
        'request_processing_time': '0.013',
        'response_processing_time': '0.000',
        'sent_bytes': 107999,
        'ssl_cipher': 'ECDHE-RSA-AES128-GCM-SHA256',
        'ssl_protocol': 'TLSv1.2',
        'destination_group_arn': (
            'arn:aws:elasticloadbalancing:us-east-2:123456789123'),
        'destination_ip_address': '192.168.1.123',
        'destination_port': 32869,
        'destination_list': ['192.168.1.123:32869'],
        'destination_processing_time': '0.164',
        'destination_status_code': 200,
        'destination_status_code_list': '200',
        'timestamp': '2020-01-11 16:55:19.000000',
        'trace_identifier': '"XXXXXXX"',
        'request_type': 'https',
        'user_agent': (
            'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; '
            'Trident/6.0)')}
    self.CheckEventValues(storage_writer, events[0], expected_event_values)

    expected_event_values = {
        'actions_executed': 'waf,forward',
        'chosen_cert_arn': 'arn:aws:abc:us-east-2:234567891234:certificate',
        'classification': '-',
        'classification_reason': '-',
        'source_ip_address': '192.168.1.10',
        'source_port': 44325,
        'data_type': 'aws:elb:access',
        'domain_name': 'www.domain.name',
        'resource_identifier': 'app/production-web/jf29fj2198ejf922',
        'elb_status_code': 200,
        'error_reason': '-',
        'matched_rule_priority': 2,
        'received_bytes': 391,
        'redirect_url': '-',
        'request': 'GET https://www.domain.name:443/ HTTP/1.1',
        'request_processing_time': '0.013',
        'response_processing_time': '0.000',
        'sent_bytes': 107999,
        'ssl_cipher': 'ECDHE-RSA-AES128-GCM-SHA256',
        'ssl_protocol': 'TLSv1.2',
        'destination_group_arn': (
            'arn:aws:elasticloadbalancing:us-east-2:123456789123'),
        'destination_ip_address': '192.168.1.123',
        'destination_port': 32869,
        'destination_list': ['192.168.1.123:32869'],
        'destination_processing_time': '0.164',
        'destination_status_code': 200,
        'destination_status_code_list': '200',
        'timestamp': '2020-01-11 16:55:20.000000',
        'trace_identifier': '"XXXXXXX"',
        'request_type': 'https',
        'user_agent': (
            'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; '
            'Trident/6.0)')}
    self.CheckEventValues(storage_writer, events[1], expected_event_values)

    expected_event_values = {
        'timestamp': '2021-05-13 23:39:43.000000',
        'resource_identifier': 'my-loadbalancer',
        'source_ip_address': '192.168.131.39',
        'source_port': 2817,
        'destination_ip_address': '10.0.0.1',
        'destination_port': 80,
        'request_processing_time': '0.000073',
        'destination_processing_time': '0.001048',
        'response_processing_time': '0.000057',
        'elb_status_code': 200,
        'destination_status_code': 200,
        'received_bytes': 0,
        'sent_bytes': 29,
        'request': 'GET http://www.example.com:80/ HTTP/1.1',
        'user_agent': 'curl/7.38.0',
        'ssl_cipher': '-',
        'ssl_protocol': '-'
    }
    self.CheckEventValues(storage_writer, events[20], expected_event_values)

    expected_event_values = {
        'timestamp': '2021-05-13 23:39:46.000000',
        'resource_identifier': 'my-loadbalancer',
        'source_ip_address': '192.168.131.39',
        'source_port': 2817,
        'destination_ip_address': '10.0.0.1',
        'destination_port': 80,
        'request_processing_time': '0.001065',
        'destination_processing_time': '0.000015',
        'response_processing_time': '0.000023',
        'elb_status_code': '-',
        'destination_status_code': '-',
        'received_bytes': '-1',
        'sent_bytes': '-1',
        'request': '- - - ',
        'user_agent': '-',
        'ssl_cipher': 'ECDHE-ECDSA-AES128-GCM-SHA256',
        'ssl_protocol': 'TLSv1.2'
    }
    self.CheckEventValues(storage_writer, events[23], expected_event_values)

    # TODO: add test for request_creation_time event
    # '2020-01-11T16:55:19.624000Z'


if __name__ == '__main__':
  unittest.main()
