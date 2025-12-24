# Tests des Routes - Guide d'utilisation

Ce répertoire contient les tests unitaires pour les routes de l'application ElasMISP.

## Structure

```
tests/
├── __init__.py           # Package tests
├── conftest.py           # Configuration pytest et fixtures
├── routes/               # Tests des routes
│   ├── test_auth.py      # Tests des routes d'authentification
│   ├── test_main.py      # Tests des routes principales
│   ├── test_ioc.py       # Tests des routes IOC
│   └── test_search.py    # Tests des routes de recherche
```

## Installation des dépendances

Installez les packages de test requis:

```bash
pip install pytest pytest-cov pytest-mock flask-testing
```

## Exécution des tests

### Tous les tests
```bash
pytest
```

### Tests spécifiques
```bash
pytest tests/routes/test_auth.py  # Tests d'authentification
pytest tests/routes/test_ioc.py   # Tests IOC
pytest -v                          # Mode verbeux
```

### Avec couverture de code
```bash
pytest --cov=app --cov-report=html
```

### Tests spécifiques
```bash
pytest tests/routes/test_auth.py::TestAuthRoutes::test_login_get_returns_template
```

## Fixtures disponibles

### `app`
Crée une application Flask de test configurée.

```python
def test_something(app):
    with app.app_context():
        # tests
```

### `client`
Crée un client test pour les requêtes HTTP.

```python
def test_api(client):
    response = client.get('/api/endpoint')
    assert response.status_code == 200
```

### `app_context`
Fournit un contexte d'application active.

```python
def test_with_context(app_context):
    # code qui nécessite app.app_context()
```

### `mock_user`
Crée un utilisateur mock prêt à l'emploi.

```python
def test_auth(client, mock_user):
    with patch('flask_login.current_user', mock_user):
        response = client.get('/dashboard')
```

### `authenticated_client`
Client avec authentification déjà configurée.

```python
def test_authenticated(authenticated_client):
    response = authenticated_client.get('/protected')
```

### `sample_ioc_data`
Données d'exemple pour créer un IOC.

```python
def test_create_ioc(client, mock_user, sample_ioc_data):
    # utiliser sample_ioc_data
```

### `sample_user_data`
Données d'exemple pour créer un utilisateur.

```python
def test_register(client, sample_user_data):
    # utiliser sample_user_data
```

### `mock_ioc_service`
Service IOC mocké.

```python
def test_ioc_service(mock_ioc_service):
    mock_ioc_service.get.return_value = {...}
```

## Ecrire des tests

### Exemple de test simple

```python
class TestMyRoutes:
    """Tests des routes personnalisées."""

    def test_endpoint_returns_200(self, client):
        """Test que l'endpoint retourne 200."""
        response = client.get('/my-endpoint')
        assert response.status_code == 200

    def test_endpoint_requires_auth(self, client):
        """Test que l'endpoint nécessite une authentification."""
        response = client.get('/protected-endpoint')
        assert response.status_code == 302  # Redirect to login
```

### Exemple avec mocks

```python
def test_create_with_mock(self, client, mock_user):
    """Test création avec mock du service."""
    mock_service = Mock()
    mock_service.create = Mock(return_value=(data, True))
    
    with patch('flask_login.current_user', mock_user):
        with patch('app.routes.module.Service', return_value=mock_service):
            response = client.post('/create', json={...})
            assert response.status_code == 201
```

## Marqueurs de tests

Marquez les tests avec des catégories:

```python
@pytest.mark.unit
def test_something():
    pass

@pytest.mark.slow
def test_slow_operation():
    pass
```

Exécutez par marqueur:
```bash
pytest -m unit
pytest -m "not slow"
```

## Bonnes pratiques

1. **Nommage**: `test_<function>_<scenario>`
   - ✅ `test_login_with_valid_credentials`
   - ❌ `test_login`

2. **Isolation**: Chaque test doit être indépendant
   - Utilisez les fixtures pour les données communes
   - Mockez les dépendances externes

3. **Assertions claires**: Une assertion par comportement testé
   - ✅ Vérifiez le statut, les données, les appels de service
   - ❌ Assertions multiples non reliées

4. **Arrange-Act-Assert**:
   ```python
   # Arrange
   mock_user = Mock()
   
   # Act
   response = client.get('/endpoint')
   
   # Assert
   assert response.status_code == 200
   ```

5. **Testez les erreurs**:
   - Requêtes invalides (400)
   - Authentification requise (401/302)
   - Ressource non trouvée (404)
   - Erreurs serveur (500)

## Couverture de code

Générez un rapport de couverture:

```bash
pytest --cov=app --cov-report=html --cov-report=term
```

Ouvrez `htmlcov/index.html` pour voir la couverture détaillée.

Objectif: Maintenir une couverture > 80% des routes critiques.

## Dépannage

### Tests qui échouent après des changements

1. Vérifiez que les chemins d'import sont corrects
2. Vérifiez que les signatures des fonctions mockées correspondent
3. Utilisez `pytest -vv` pour plus de détails

### Problèmes d'authentification

- Assurez-vous que `current_user` est mocké correctement
- Utilisez `@patch('flask_login.current_user', mock_user)`
- Vérifiez que `mock_user.is_authenticated = True`

### Erreurs de contexte Flask

- Utilisez `app_context` ou `client` qui gère automatiquement le contexte
- Pour les opérations sans client, utilisez `app.app_context()`

## CI/CD Integration

Pour intégrer les tests dans CI/CD:

```yaml
# Exemple GitHub Actions
- name: Run tests
  run: pytest --cov=app --cov-report=xml

- name: Upload coverage
  uses: codecov/codecov-action@v3
```

## Ressources

- [Documentation pytest](https://docs.pytest.org/)
- [Flask Testing](https://flask.palletsprojects.com/testing/)
- [unittest.mock](https://docs.python.org/3/library/unittest.mock.html)
