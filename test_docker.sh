#!/bin/bash
# Script pour exécuter les tests dans Docker avec Elasticsearch et Redis

set -e

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}🐳 ElasMISP - Exécution des tests dans Docker${NC}"
echo "=============================================="
echo ""

# Configuration
COMPOSE_FILE="docker-compose.test.yml"
TEST_SERVICE="test"
VENV_VERSION="311"

# Vérifier que docker-compose existe
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}❌ docker-compose n'est pas installé${NC}"
    exit 1
fi

# Vérifier que Docker est en cours d'exécution
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}❌ Docker n'est pas en cours d'exécution${NC}"
    exit 1
fi

# Étape 1: Arrêter les conteneurs existants
echo -e "${YELLOW}1️⃣  Arrêt des conteneurs existants...${NC}"
docker-compose -f $COMPOSE_FILE down --remove-orphans 2>/dev/null || true
echo -e "${GREEN}✅ Fait${NC}"
echo ""

# Étape 2: Lancer Elasticsearch et Redis
echo -e "${YELLOW}2️⃣  Lancement d'Elasticsearch et Redis...${NC}"
docker-compose -f $COMPOSE_FILE up -d elasticsearch redis

# Attendre qu'Elasticsearch soit prêt
echo -e "${YELLOW}⏳ Attente d'Elasticsearch...${NC}"
for i in {1..30}; do
    if curl -s http://localhost:9200 >/dev/null 2>&1; then
        echo -e "${GREEN}✅ Elasticsearch est prêt${NC}"
        break
    fi
    echo "  Tentative $i/30..."
    sleep 2
done
echo ""

# Étape 3: Vérifier que Redis est prêt
echo -e "${YELLOW}⏳ Vérification de Redis...${NC}"
if command -v redis-cli &> /dev/null; then
    for i in {1..10}; do
        if redis-cli -p 6379 ping >/dev/null 2>&1; then
            echo -e "${GREEN}✅ Redis est prêt${NC}"
            break
        fi
        sleep 1
    done
fi
echo ""

# Étape 4: Initialiser Elasticsearch
echo -e "${YELLOW}3️⃣  Initialisation d'Elasticsearch...${NC}"
if [ -f "scripts/init_elasticsearch.py" ]; then
    if [ -d "venv$VENV_VERSION" ]; then
        source venv$VENV_VERSION/bin/activate
        ELASTICSEARCH_URL=http://localhost:9200 python scripts/init_elasticsearch.py
        echo -e "${GREEN}✅ Elasticsearch initialisé${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Script init_elasticsearch.py non trouvé${NC}"
fi
echo ""

# Étape 5: Exécuter les tests
echo -e "${YELLOW}4️⃣  Exécution des tests...${NC}"
if [ -d "venv$VENV_VERSION" ]; then
    source venv$VENV_VERSION/bin/activate
    
    # Appliquer les arguments passés au script
    PYTEST_ARGS="${@:-.}"
    
    echo "Commande: pytest $PYTEST_ARGS"
    pytest $PYTEST_ARGS
else
    echo -e "${RED}❌ Environnement virtuel venv$VENV_VERSION non trouvé${NC}"
    echo "Créer d'abord le venv avec: ./setup_tests.sh"
    exit 1
fi

TEST_EXIT_CODE=$?
echo ""

# Étape 6: Nettoyage optionnel
if [ "$1" != "--keep-docker" ]; then
    echo -e "${YELLOW}5️⃣  Nettoyage des conteneurs Docker...${NC}"
    docker-compose -f $COMPOSE_FILE down --remove-orphans
    echo -e "${GREEN}✅ Conteneurs arrêtés${NC}"
else
    echo -e "${YELLOW}ℹ️  Les conteneurs Docker restent actifs (option --keep-docker utilisée)${NC}"
fi

echo ""
if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✅ Tous les tests ont réussi!${NC}"
else
    echo -e "${RED}❌ Certains tests ont échoué (code: $TEST_EXIT_CODE)${NC}"
fi

exit $TEST_EXIT_CODE
