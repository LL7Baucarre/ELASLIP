#!/usr/bin/env python3
"""Test script to verify Ollama/LLM connection and generate sample report."""

import sys
import os
import requests
from dotenv import load_dotenv

load_dotenv()

def test_llm_connection():
    """Test connection to LLM provider."""
    llm_url = os.getenv('LLM_URL', 'http://localhost:11434')
    
    print(f"Testing connection to LLM at {llm_url}...")
    
    try:
        response = requests.get(f"{llm_url}/api/tags", timeout=5)
        if response.status_code == 200:
            data = response.json()
            models = [m['name'] for m in data.get('models', [])]
            print(f"✓ Connection successful!")
            print(f"  Available models: {', '.join(models) if models else 'None'}")
            return True
        else:
            print(f"✗ Connection failed with status {response.status_code}")
            return False
    except requests.RequestException as e:
        print(f"✗ Connection failed: {str(e)}")
        print(f"  Make sure Ollama is running: ollama serve")
        return False


def test_generate_prompt():
    """Test generating a report with sample data."""
    llm_url = os.getenv('LLM_URL', 'http://localhost:11434')
    llm_model = os.getenv('LLM_MODEL', 'mistral')
    
    print(f"\nTesting report generation with {llm_model}...")
    print("This may take a minute...")
    
    prompt = """Analyze this Indicator of Compromise (IOC) and provide a concise threat assessment:

IOC Type: ipv4
IOC Value: 192.168.1.100
Severity: high
Description: Detected as C2 server

Please provide:
1. What this indicator represents
2. Potential threats it indicates
3. Recommended mitigation steps"""
    
    try:
        headers = {'Content-Type': 'application/json'}
        api_key = os.getenv('LLM_API_KEY', '')
        if api_key:
            headers['Authorization'] = f'Bearer {api_key}'
        
        payload = {
            'model': llm_model,
            'prompt': prompt,
            'stream': False,
        }
        
        response = requests.post(
            f"{llm_url}/api/generate",
            json=payload,
            headers=headers,
            timeout=180
        )
        response.raise_for_status()
        
        data = response.json()
        result = data.get('response', '').strip()
        
        if result:
            print(f"✓ Report generated successfully!")
            print("\n--- Generated Report ---")
            print(result)
            print("--- End Report ---\n")
            return True
        else:
            print("✗ No response from LLM")
            return False
            
    except requests.Timeout:
        print("✗ Request timeout - LLM took too long to respond")
        return False
    except requests.RequestException as e:
        print(f"✗ Report generation failed: {str(e)}")
        return False


def main():
    """Run all tests."""
    print("=" * 50)
    print("LLM Configuration Test")
    print("=" * 50)
    
    # Test connection
    if not test_llm_connection():
        print("\n✗ LLM connection test failed")
        print("\nSetup instructions:")
        print("1. Install Ollama: https://ollama.ai")
        print("2. Pull a model: ollama pull mistral")
        print("3. Start Ollama: ollama serve")
        return 1
    
    # Test generation
    if not test_generate_prompt():
        print("\n✗ Report generation test failed")
        return 1
    
    print("\n" + "=" * 50)
    print("✓ All tests passed! LLM is ready to use")
    print("=" * 50)
    print("\nEnable LLM in ElasMISP:")
    print("1. Set LLM_ENABLED=true in .env")
    print("2. Go to Settings → LLM Reports")
    print("3. Configure and test the connection")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
