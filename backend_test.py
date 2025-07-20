#!/usr/bin/env python3
"""
JADE Ultimate Security Platform - Backend API Testing
Tests all AI integrations and core endpoints
"""

import asyncio
import httpx
import json
import time
from typing import Dict, Any, List
import sys
import os

# Backend URL - using the actual running port
BACKEND_URL = "http://localhost:8001"
API_BASE = f"{BACKEND_URL}/api/v1"

# Mock authentication token for testing
MOCK_TOKEN = "test_token_jade_security_2025"

class BackendTester:
    def __init__(self):
        self.client = httpx.AsyncClient(timeout=30.0)
        self.results = {
            "health_check": {"status": "pending", "details": {}},
            "ai_models": {"status": "pending", "details": {}},
            "ai_tests": {"status": "pending", "details": {}},
            "dashboard_stats": {"status": "pending", "details": {}},
            "summary": {"total_tests": 0, "passed": 0, "failed": 0}
        }
        
    async def __aenter__(self):
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()

    def log_test(self, test_name: str, status: str, details: Any = None):
        """Log test results"""
        print(f"[{status.upper()}] {test_name}")
        if details:
            print(f"  Details: {details}")
        print()

    async def test_health_endpoint(self) -> bool:
        """Test the /health endpoint"""
        print("=" * 60)
        print("TESTING: Health Check Endpoint")
        print("=" * 60)
        
        try:
            response = await self.client.get(f"{BACKEND_URL}/health")
            
            if response.status_code == 200:
                data = response.json()
                self.results["health_check"] = {
                    "status": "passed",
                    "details": {
                        "status_code": response.status_code,
                        "response": data,
                        "has_status": "status" in data,
                        "has_version": "version" in data,
                        "has_creator": "creator" in data
                    }
                }
                self.log_test("Health Check", "PASSED", data)
                return True
            else:
                self.results["health_check"] = {
                    "status": "failed",
                    "details": {
                        "status_code": response.status_code,
                        "error": response.text
                    }
                }
                self.log_test("Health Check", "FAILED", f"Status: {response.status_code}")
                return False
                
        except Exception as e:
            self.results["health_check"] = {
                "status": "failed",
                "details": {"error": str(e)}
            }
            self.log_test("Health Check", "FAILED", str(e))
            return False

    async def test_ai_models_endpoint(self) -> bool:
        """Test the /api/v1/ai/models endpoint"""
        print("=" * 60)
        print("TESTING: AI Models Endpoint")
        print("=" * 60)
        
        try:
            # First, let's try without authentication to see what happens
            response = await self.client.get(f"{API_BASE}/ai/models")
            
            if response.status_code == 401:
                print("Authentication required - this is expected behavior")
                # Try with mock token in header
                headers = {"Authorization": f"Bearer {MOCK_TOKEN}"}
                response = await self.client.get(f"{API_BASE}/ai/models", headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                models = data.get("models", {})
                
                expected_models = ["gpt-4", "gpt-4-turbo", "gpt-4.1", "grok-3", "llama-4-scout", "gemini-pro"]
                found_models = list(models.keys())
                
                # Check which models are available
                available_models = {k: v for k, v in models.items() if v.get("available", False)}
                
                self.results["ai_models"] = {
                    "status": "passed",
                    "details": {
                        "status_code": response.status_code,
                        "total_models": len(models),
                        "expected_models": expected_models,
                        "found_models": found_models,
                        "available_models": list(available_models.keys()),
                        "models_data": models
                    }
                }
                
                print(f"Total models configured: {len(models)}")
                print(f"Available models: {list(available_models.keys())}")
                print(f"Expected models: {expected_models}")
                print(f"Found models: {found_models}")
                
                for model_name, model_info in models.items():
                    status = "✅ AVAILABLE" if model_info.get("available") else "❌ UNAVAILABLE"
                    provider = model_info.get("provider", "unknown")
                    print(f"  {model_name} ({provider}): {status}")
                
                self.log_test("AI Models Endpoint", "PASSED", f"Found {len(models)} models, {len(available_models)} available")
                return True
                
            else:
                self.results["ai_models"] = {
                    "status": "failed",
                    "details": {
                        "status_code": response.status_code,
                        "error": response.text
                    }
                }
                self.log_test("AI Models Endpoint", "FAILED", f"Status: {response.status_code}, Error: {response.text}")
                return False
                
        except Exception as e:
            self.results["ai_models"] = {
                "status": "failed",
                "details": {"error": str(e)}
            }
            self.log_test("AI Models Endpoint", "FAILED", str(e))
            return False

    async def test_ai_model(self, model_name: str) -> bool:
        """Test a specific AI model"""
        print(f"Testing AI Model: {model_name}")
        
        try:
            headers = {"Authorization": f"Bearer {MOCK_TOKEN}"}
            response = await self.client.post(f"{API_BASE}/ai/test/{model_name}", headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                print(f"  ✅ {model_name}: SUCCESS")
                print(f"     Provider: {data.get('provider', 'unknown')}")
                print(f"     Response: {data.get('response', 'No response')[:100]}...")
                print(f"     Latency: {data.get('latency_ms', 'unknown')}ms")
                return True
            else:
                print(f"  ❌ {model_name}: FAILED - Status {response.status_code}")
                print(f"     Error: {response.text}")
                return False
                
        except Exception as e:
            print(f"  ❌ {model_name}: ERROR - {str(e)}")
            return False

    async def test_ai_models_functionality(self) -> bool:
        """Test AI models functionality"""
        print("=" * 60)
        print("TESTING: AI Models Functionality")
        print("=" * 60)
        
        # Get available models first
        if self.results["ai_models"]["status"] != "passed":
            print("Skipping AI model tests - models endpoint failed")
            return False
            
        available_models = self.results["ai_models"]["details"]["available_models"]
        
        if not available_models:
            print("No available AI models to test")
            self.results["ai_tests"] = {
                "status": "failed",
                "details": {"error": "No available models"}
            }
            return False
        
        print(f"Testing {len(available_models)} available models...")
        
        test_results = {}
        successful_tests = 0
        
        for model in available_models:
            success = await self.test_ai_model(model)
            test_results[model] = success
            if success:
                successful_tests += 1
        
        self.results["ai_tests"] = {
            "status": "passed" if successful_tests > 0 else "failed",
            "details": {
                "total_tested": len(available_models),
                "successful": successful_tests,
                "failed": len(available_models) - successful_tests,
                "results": test_results
            }
        }
        
        print(f"\nAI Model Testing Summary:")
        print(f"  Total tested: {len(available_models)}")
        print(f"  Successful: {successful_tests}")
        print(f"  Failed: {len(available_models) - successful_tests}")
        
        self.log_test("AI Models Functionality", "PASSED" if successful_tests > 0 else "FAILED", 
                     f"{successful_tests}/{len(available_models)} models working")
        
        return successful_tests > 0

    async def test_dashboard_stats(self) -> bool:
        """Test the /api/v1/dashboard/stats endpoint"""
        print("=" * 60)
        print("TESTING: Dashboard Stats Endpoint")
        print("=" * 60)
        
        try:
            headers = {"Authorization": f"Bearer {MOCK_TOKEN}"}
            response = await self.client.get(f"{API_BASE}/dashboard/stats", headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                
                expected_fields = ["total_scans", "active_scans", "vulnerabilities_found", 
                                 "critical_issues", "ai_models_available"]
                
                has_all_fields = all(field in data for field in expected_fields)
                
                self.results["dashboard_stats"] = {
                    "status": "passed",
                    "details": {
                        "status_code": response.status_code,
                        "response": data,
                        "has_all_fields": has_all_fields,
                        "expected_fields": expected_fields,
                        "found_fields": list(data.keys())
                    }
                }
                
                print("Dashboard Stats Response:")
                for key, value in data.items():
                    print(f"  {key}: {value}")
                
                self.log_test("Dashboard Stats", "PASSED", f"All expected fields present: {has_all_fields}")
                return True
                
            else:
                self.results["dashboard_stats"] = {
                    "status": "failed",
                    "details": {
                        "status_code": response.status_code,
                        "error": response.text
                    }
                }
                self.log_test("Dashboard Stats", "FAILED", f"Status: {response.status_code}")
                return False
                
        except Exception as e:
            self.results["dashboard_stats"] = {
                "status": "failed",
                "details": {"error": str(e)}
            }
            self.log_test("Dashboard Stats", "FAILED", str(e))
            return False

    async def run_all_tests(self):
        """Run all backend tests"""
        print("🚀 JADE Ultimate Security Platform - Backend API Testing")
        print("=" * 80)
        print(f"Backend URL: {BACKEND_URL}")
        print(f"API Base: {API_BASE}")
        print("=" * 80)
        
        tests = [
            ("Health Check", self.test_health_endpoint),
            ("AI Models", self.test_ai_models_endpoint),
            ("AI Functionality", self.test_ai_models_functionality),
            ("Dashboard Stats", self.test_dashboard_stats)
        ]
        
        total_tests = len(tests)
        passed_tests = 0
        
        for test_name, test_func in tests:
            try:
                result = await test_func()
                if result:
                    passed_tests += 1
            except Exception as e:
                print(f"❌ {test_name} failed with exception: {e}")
        
        # Update summary
        self.results["summary"] = {
            "total_tests": total_tests,
            "passed": passed_tests,
            "failed": total_tests - passed_tests
        }
        
        # Print final summary
        print("=" * 80)
        print("🎯 FINAL TEST SUMMARY")
        print("=" * 80)
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests} ✅")
        print(f"Failed: {total_tests - passed_tests} ❌")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        
        # Detailed results
        print("\n📊 DETAILED RESULTS:")
        print("-" * 40)
        
        for test_category, result in self.results.items():
            if test_category == "summary":
                continue
                
            status = result.get("status", "unknown")
            status_icon = "✅" if status == "passed" else "❌" if status == "failed" else "⏳"
            print(f"{status_icon} {test_category.replace('_', ' ').title()}: {status.upper()}")
        
        # AI Models specific summary
        if self.results["ai_models"]["status"] == "passed":
            models_data = self.results["ai_models"]["details"]
            available_count = len(models_data["available_models"])
            total_count = models_data["total_models"]
            print(f"\n🤖 AI MODELS SUMMARY:")
            print(f"   Total Configured: {total_count}")
            print(f"   Available: {available_count}")
            print(f"   Working Models: {', '.join(models_data['available_models'])}")
        
        if self.results["ai_tests"]["status"] == "passed":
            ai_data = self.results["ai_tests"]["details"]
            print(f"   Successfully Tested: {ai_data['successful']}/{ai_data['total_tested']}")
        
        print("=" * 80)
        
        return passed_tests == total_tests

async def main():
    """Main test runner"""
    async with BackendTester() as tester:
        success = await tester.run_all_tests()
        
        # Save results to file
        with open("/app/backend_test_results.json", "w") as f:
            json.dump(tester.results, f, indent=2)
        
        print(f"\n📁 Test results saved to: /app/backend_test_results.json")
        
        if success:
            print("🎉 All tests passed!")
            sys.exit(0)
        else:
            print("⚠️  Some tests failed. Check the results above.")
            sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())