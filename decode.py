import base64
import re

def decode_obfuscated_python(file_path):
    """
    Obfuscate edilmiş Python dosyasını decode eder
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        print("📁 Orijinal dosya içeriği:")
        print("=" * 50)
        print(content[:500] + "..." if len(content) > 500 else content)
        print("=" * 50)
        
        # Lambda ifadesini bulmaya çalış
        lambda_pattern = r'_ = lambda __ : __import__\(\'base64\'\)\.b64decode\(__\[::\-1\]\)\;exec\(\(_\)\(b\'([^\']+)\'\)\)'
        match = re.search(lambda_pattern, content)
        
        if match:
            print("✅ Lambda obfuscation pattern bulundu!")
            encoded_data = match.group(1)
            
            # Decode işlemi
            print("\n🔄 Decode işlemi yapılıyor...")
            
            # Base64 decode (ters çevrilmiş)
            reversed_data = encoded_data[::-1]
            decoded_bytes = base64.b64decode(reversed_data)
            
            try:
                decoded_content = decoded_bytes.decode('utf-8')
            except:
                decoded_content = decoded_bytes.decode('latin-1')
            
            print("✅ İlk katman decode edildi!")
            
            # Decode edilen içerikte tekrar base64 pattern ara
            additional_b64 = re.findall(r'b\'([A-Za-z0-9+/=]+)\'', decoded_content)
            
            results = {
                'first_layer': decoded_content,
                'additional_b64': additional_b64
            }
            
            return results
            
        else:
            print("❌ Standart lambda pattern bulunamadı, alternatif pattern aranıyor...")
            
            # Alternatif pattern: base64 strings
            b64_pattern = r'b\'([A-Za-z0-9+/=]+)\''
            b64_matches = re.findall(b64_pattern, content)
            
            if b64_matches:
                print(f"✅ {len(b64_matches)} adet base64 string bulundu")
                return {'b64_strings': b64_matches}
            else:
                return {'error': 'Decode edilebilir pattern bulunamadı'}
                
    except Exception as e:
        return {'error': f'Hata: {str(e)}'}

def deep_decode_b64_strings(b64_strings):
    """
    Base64 string'leri derinlemesine decode eder
    """
    results = []
    
    for i, b64_str in enumerate(b64_strings):
        print(f"\n🔍 {i+1}. base64 string decode ediliyor...")
        
        try:
            # Base64 decode
            decoded_bytes = base64.b64decode(b64_str)
            
            # UTF-8 decode dene
            try:
                decoded_text = decoded_bytes.decode('utf-8')
                results.append({
                    'original': b64_str[:100] + '...' if len(b64_str) > 100 else b64_str,
                    'decoded': decoded_text,
                    'is_text': True
                })
                print(f"✅ Text içerik decode edildi")
                
            except:
                # Binary data olabilir
                results.append({
                    'original': b64_str[:100] + '...' if len(b64_str) > 100 else b64_str,
                    'decoded_bytes': decoded_bytes,
                    'is_text': False,
                    'hex_preview': decoded_bytes.hex()[:100] + '...'
                })
                print(f"⚠️ Binary data detect edildi")
                
        except Exception as e:
            results.append({
                'original': b64_str[:100] + '...' if len(b64_str) > 100 else b64_str,
                'error': str(e)
            })
            print(f"❌ Decode hatası: {e}")
    
    return results

def save_decoded_content(content, filename):
    """
    Decode edilmiş içeriği dosyaya kaydeder
    """
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"💾 Decode edilmiş içerik '{filename}' dosyasına kaydedildi")
    except Exception as e:
        print(f"❌ Dosya kaydetme hatası: {e}")

def analyze_decoded_content(content):
    """
    Decode edilmiş içeriği analiz eder
    """
    print("\n🔍 Decode edilmiş içerik analizi:")
    print("=" * 50)
    
    # İçerik uzunluğu
    print(f"📏 İçerik uzunluğu: {len(content)} karakter")
    
    # Satır sayısı
    lines = content.split('\n')
    print(f"📄 Satır sayısı: {len(lines)}")
    
    # İlk 10 satırı göster
    print("\n📝 İlk 10 satır:")
    for i, line in enumerate(lines[:10]):
        print(f"{i+1:2d}: {line[:100]}{'...' if len(line) > 100 else ''}")
    
    # Önemli keyword'ler
    keywords = ['import', 'exec', 'eval', 'base64', 'requests', 'os.', 'sys.', 'subprocess', 
                'Crypto', 'AES', 'urllib', 'http', 'socket', 'open(']
    
    print("\n🔑 Tespit edilen önemli keyword'ler:")
    found_keywords = []
    for keyword in keywords:
        if keyword in content:
            found_keywords.append(keyword)
    
    if found_keywords:
        for kw in found_keywords:
            count = content.count(kw)
            print(f"   - {kw}: {count} kez")
    else:
        print("   - Önemli keyword bulunamadı")
    
    # Şüpheli pattern'ler
    suspicious = ['__import__', 'compile(', 'getattr', 'setattr', 'globals()', 'locals()']
    suspicious_found = [s for s in suspicious if s in content]
    
    if suspicious_found:
        print("\n⚠️ ŞÜPHELİ PATTERN'LER TESPİT EDİLDİ:")
        for s in suspicious_found:
            print(f"   - {s}")

def main():
    """
    Ana decode fonksiyonu
    """
    print("🐍 Python Obfuscation Decode Aracı")
    print("=" * 40)
    
    # Kullanıcıdan dosya yolu al
    file_path = input("Decode edilecek Python dosyasının yolunu girin: ").strip()
    
    if not file_path:
        file_path = "morfinaxeinstatool.py"  # Varsayılan
    
    try:
        # Dosyayı decode et
        result = decode_obfuscated_python(file_path)
        
        if 'error' in result:
            print(f"❌ {result['error']}")
            return
        
        # İlk katman decode sonuçları
        if 'first_layer' in result:
            first_layer = result['first_layer']
            
            print("\n" + "="*60)
            print("🎯 İLK KATMAN DECODE SONUCU:")
            print("="*60)
            print(first_layer)
            
            # Analiz yap
            analyze_decoded_content(first_layer)
            
            # Dosyaya kaydet
            save_decoded_content(first_layer, "decoded_layer1.py")
            
            # Ek base64 string'leri kontrol et
            if result['additional_b64']:
                print(f"\n🔄 Ek {len(result['additional_b64'])} base64 string decode ediliyor...")
                deep_results = deep_decode_b64_strings(result['additional_b64'])
                
                for i, res in enumerate(deep_results):
                    print(f"\n📦 {i+1}. Decode Sonucu:")
                    if 'decoded' in res and res['is_text']:
                        print(f"   Text: {res['decoded'][:200]}...")
                    elif 'hex_preview' in res:
                        print(f"   Binary (hex): {res['hex_preview']}")
                    elif 'error' in res:
                        print(f"   Hata: {res['error']}")
        
        # Sadece base64 string'ler varsa
        elif 'b64_strings' in result:
            b64_strings = result['b64_strings']
            print(f"\n🔄 {len(b64_strings)} adet base64 string decode ediliyor...")
            deep_results = deep_decode_b64_strings(b64_strings)
            
            for i, res in enumerate(deep_results):
                print(f"\n🎯 {i+1}. Decode Sonucu:")
                if 'decoded' in res and res['is_text']:
                    print(res['decoded'])
                    save_decoded_content(res['decoded'], f"decoded_b64_{i+1}.py")
                elif 'hex_preview' in res:
                    print(f"Binary data: {res['hex_preview']}")
                elif 'error' in res:
                    print(f"Hata: {res['error']}")
    
    except FileNotFoundError:
        print(f"❌ Dosya bulunamadı: {file_path}")
    except Exception as e:
        print(f"❌ Beklenmeyen hata: {e}")

if __name__ == "__main__":
    main()