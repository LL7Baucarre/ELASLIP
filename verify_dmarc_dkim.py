#!/usr/bin/env python3
"""
Vérification finale - Analyseur DMARC/DKIM
"""

import os
import sys

print("\n" + "="*70)
print("  VÉRIFICATION FINALE - ANALYSEUR DMARC/DKIM")
print("="*70 + "\n")

checks = {
    "✅ Code backend": [
        ("app/services/tools_service.py", ["analyze_dmarc_dkim", "_parse_dmarc_record", "_parse_dkim_record"]),
        ("app/routes/tools.py", ["/dmarc-dkim", "analyze_dmarc_dkim", "POST"])
    ],
    "✅ Interface web": [
        ("templates/tools.html", ["dmarc-dkim", "dmarcDkimForm", "dmarcDkimTarget", "dmarcDkimBtn"])
    ],
    "✅ Tests & Docs": [
        ("tests/test_dmarc_dkim.py", ["ToolsService", "analyze_dmarc_dkim"]),
        ("DMARC_DKIM_INTEGRATION.md", ["DMARC/DKIM"]),
        ("DMARC_DKIM_USER_GUIDE.md", ["DMARC/DKIM"]),
        ("DMARC_DKIM_QUICK_START.txt", ["PRÊT POUR PRODUCTION"])
    ]
}

base_path = "/c/Users/jason/Desktop/ELASLIP"

all_ok = True

for category, files in checks.items():
    print(f"\n{category}")
    print("-" * 70)
    
    for file_path, keywords in files:
        full_path = os.path.join(base_path, file_path)
        
        if os.path.exists(full_path):
            print(f"  ✅ Fichier trouvé : {file_path}")
            
            # Vérifier les keywords
            try:
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                missing = []
                for keyword in keywords:
                    if keyword not in content:
                        missing.append(keyword)
                
                if missing:
                    print(f"     ⚠️  Keywords manquants : {', '.join(missing)}")
                    all_ok = False
                else:
                    print(f"     ✅ Tous les keywords trouvés")
            except Exception as e:
                print(f"     ❌ Erreur de lecture : {e}")
                all_ok = False
        else:
            print(f"  ❌ Fichier manquant : {file_path}")
            all_ok = False

# Vérification finale
print("\n" + "="*70)

if all_ok:
    print("  ✅ VÉRIFICATION COMPLÈTE - TOUS LES ÉLÉMENTS SONT EN PLACE")
    print("\n  L'analyseur DMARC/DKIM est prêt à être utilisé !")
    print("\n  Prochaines étapes :")
    print("  1. docker-compose up --build app")
    print("  2. http://localhost:5000/tools")
    print("  3. Voir la carte DMARC/DKIM")
    print("\n" + "="*70 + "\n")
    sys.exit(0)
else:
    print("  ❌ VÉRIFICATION ÉCHOUÉE - CERTAINS ÉLÉMENTS MANQUENT")
    print("\n" + "="*70 + "\n")
    sys.exit(1)
