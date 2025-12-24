#!/usr/bin/env python
"""Script pour exécuter les tests avec options communes."""

import subprocess
import sys
import argparse


def run_tests(args):
    """Exécuter les tests pytest."""
    cmd = ['pytest']
    
    # Ajouter le chemin des tests
    if args.test_path:
        cmd.append(args.test_path)
    else:
        cmd.append('tests/')
    
    # Options verbosité
    if args.verbose:
        cmd.append('-v')
    if args.very_verbose:
        cmd.append('-vv')
    
    # Couverture
    if args.coverage:
        cmd.extend(['--cov=app', '--cov-report=html', '--cov-report=term'])
    
    # Marqueurs
    if args.marker:
        cmd.extend(['-m', args.marker])
    
    # Mode strict
    if args.strict:
        cmd.append('--strict-markers')
    
    # Arrêter au premier echec
    if args.failfast:
        cmd.append('-x')
    
    # Nombre de workers parallèles
    if args.workers:
        cmd.extend(['-n', str(args.workers)])
    
    # Rapport JUnit pour CI/CD
    if args.junit:
        cmd.extend(['--junit-xml=test-results.xml'])
    
    # Filtre par nom de test
    if args.keyword:
        cmd.extend(['-k', args.keyword])
    
    print(f"Exécution: {' '.join(cmd)}")
    return subprocess.run(cmd).returncode


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Gestionnaire de tests ElasMISP')
    
    parser.add_argument('test_path', nargs='?', help='Chemin des tests (défaut: tests/)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Mode verbeux')
    parser.add_argument('-vv', '--very-verbose', action='store_true', help='Mode très verbeux')
    parser.add_argument('-c', '--coverage', action='store_true', help='Générer rapport de couverture')
    parser.add_argument('-m', '--marker', help='Exécuter tests par marqueur')
    parser.add_argument('-s', '--strict', action='store_true', help='Mode strict')
    parser.add_argument('-x', '--failfast', action='store_true', help='Arrêter au premier échec')
    parser.add_argument('-n', '--workers', type=int, help='Nombre de workers parallèles')
    parser.add_argument('-j', '--junit', action='store_true', help='Générer rapport JUnit XML')
    parser.add_argument('-k', '--keyword', help='Filtre par nom de test')
    
    args = parser.parse_args()
    sys.exit(run_tests(args))
