#!/bin/bash
# Script de configuration pour les tests en Python 3.11

set -e

echo "🐍 Préparation de l'environnement de test ElasMISP"
echo "=================================================="
echo ""

PYTHON_VERSION="3.11"
VENV_DIR="venv311"

# Vérifier que Python 3.11 est installé
if ! command -v python3.11 &> /dev/null; then
    echo "❌ Python 3.11 n'est pas installé"
    echo "Installation sur macOS:"
    echo "  brew install python@3.11"
    exit 1
fi

echo "✅ Python 3.11 trouvé"
python3.11 --version
echo ""

# Créer le venv s'il n'existe pas
if [ ! -d "$VENV_DIR" ]; then
    echo "📦 Création de l'environnement virtuel..."
    python3.11 -m venv $VENV_DIR
    echo "✅ Venv créé"
else
    echo "✅ Venv existe déjà"
fi
echo ""

# Activer le venv
source $VENV_DIR/bin/activate
echo "✅ Venv activé"
echo ""

# Mettre à jour pip
echo "📦 Mise à jour de pip, setuptools, wheel..."
pip install --upgrade pip setuptools wheel
echo "✅ Dépendances de base mises à jour"
echo ""

# Installer les dépendances
echo "📦 Installation des dépendances..."
pip install -r requirements.txt
pip install -r requirements-test.txt
pip install --upgrade pytest-flask  # Pour compatibilité Flask 3.0
echo "✅ Dépendances installées"
echo ""

echo "🎉 Environnement de test prêt!"
echo ""
echo "Prochaines étapes:"
echo "  1. Pour lancer les tests avec Docker:"
echo "     ./test_docker.sh"
echo ""
echo "  2. Pour lancer les tests avec options spécifiques:"
echo "     ./test_docker.sh tests/routes/test_auth.py -v"
echo ""
echo "  3. Pour lancer les tests sans nettoyer Docker:"
echo "     ./test_docker.sh --keep-docker"
echo ""
