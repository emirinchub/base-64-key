#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import zlib

def encode_file(input_file, output_file):
    """Python dosyasını encode eder ve çalışır hale getirir"""
    try:
        # Orijinal dosyayı oku
        with open(input_file, 'r', encoding='utf-8') as f:
            code = f.read()
        
        # Kodu sıkıştır ve encode et
        compressed = zlib.compress(code.encode('utf-8'))
        encoded = base64.b64encode(compressed).decode('utf-8')
        
        # Çalıştırıcı kod
        runner = f'''#!/usr/bin/env python3
import base64
import zlib

exec(zlib.decompress(base64.b64decode("{encoded}")).decode('utf-8'))
'''
        
        # Çıktı dosyasını yaz
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(runner)
        
        print(f"✓ Encode edildi: {output_file}")
        return True
        
    except Exception as e:
        print(f"✗ Hata: {e}")
        return False

if __name__ == "__main__":
    input_file = input("Dosya: ")
    output_file = input_file.replace('.py', '_encoded.py')
    
    if encode_file(input_file, output_file):
        print(f"Çalıştır: python3 {output_file}")