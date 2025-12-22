import json
import requests
import time
from datetime import datetime
from typing import Dict, List, Any
import urllib3
import argparse
import sys

# Désactiver les avertissements SSL (non nécessaire pour Azure mais gardé pour compatibilité)
# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==================== CONFIGURATION GLOBALE ====================
BASE_URL = "https://fundsq-degroof-test.azurewebsites.net"
DEFAULT_STRING_VALUE = "test_value"
DEFAULT_INT_VALUE = 0
DEFAULT_BOOL_VALUE = False
DEFAULT_FLOAT_VALUE = 0.0

# Headers et cookies extraits de votre requête curl
HEADERS = {
    "accept": "*/*",
    "accept-language": "en-US,en;q=0.9,ml;q=0.8",
    "connection": "keep-alive",
    "origin": "https://fundsq-degroof-test.azurewebsites.net",
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0",
    "x-requested-with": "XMLHttpRequest",
    "sec-ch-ua": '"Microsoft Edge";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"'
}

COOKIES = {
    "TranslationCulture": "ENG",
    "__RequestVerificationToken": "nJSuzb0n01OdX9lHcSekGaAeGbuQV9Zo7AZ6Qy8wrppq35A-Yc9MbzNfP3BN8USn5gg7M9WhZvxiGd6GQEA9l_C0cvJE5-hUxVfuLt2hK_Q1",
    "ARRAffinity": "b75e77002ba89b7b27787cb1e27fb03824cd4882728e9d3f98d0a753614ce3a1",
    "ARRAffinitySameSite": "b75e77002ba89b7b27787cb1e27fb03824cd4882728e9d3f98d0a753614ce3a1",
    ".AspNet.ApplicationCookie": "27It8N-8TW4w8kT7YeluOZHRgc1baeeHQPEfIVQR1THrsyPogwG5OkjJfHRnfYFzUY27zNSD10xACaArNtXcBqEvOTGmm36rDmq5iNCVxEc3VWKhzhoGLuqHTvpYAZ3WFdMS25SKBYagSEB9LN62R6bsT0tdNrOlE8JxZgg3qkgTR__lnhss5mPVMA59dLbqSVOdrL3TWb-qfxvVzkO86so3ETvzb4s82lYASDm_Sk6uFcJukheM3UgUU9Fyc4CYbR8zQJUtecha0npX3DBn7OT5sH6ljs05BtRA6rk_g8CZ5GL8iMxsSDKud1YVeNBoMNraAaFAh3kYtO9lggkIzXRmOaMWeHhvO636wjueZ4wD0Njv2J9FeQOxzxH7dVKJunbuKY90hw59L8Au_UDN-B8_Pnm-NdM_UjYbsjsFIWK5E7eDHtp3v_4ZaVufLAqVSshj5T1GitfVM9-p8XEKATOWHIsLjTmYkmjWBTRLOOoAeX9QbVlSTm31pWJGhDj1",
    ".ASPXAUTH": "FC76777F5AB48C88F63A053E7FB873F0FBF4843304B05A1ADF64FC7E0651155DD7377C82DDA0C801FE42DB693F13F61888B8FFAD3F4ACD0B2BFBFE2DC3A3CC2D6AF4CFFCD434C83058D1488F07D813D441C90F090650490605727BBAD3B40C4612756A9BE0EE41C007C7C7D156740750321E3E09A11A0F2CA2820506A6C489134003CEA167D842B01A75CC2303AC551F",
    "ASP.NET_SessionId": "o5jlpoijisucak4khjwerhcc",
    "idleTimer": "%7B%22idleTime%22%3A%220%22%2C%22updatedTime%22%3A%22Mon%20Dec%2022%202025%2011%3A10%3A15%20GMT%2B0530%20(India%20Standard%20Time)%22%7D"

}


# Fichiers d'entrée et de sortie
INPUT_JSON_FILE = "endpoints.json"
OUTPUT_RESULTS_FILE = f"test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

# ==================== FONCTIONS UTILITAIRES ====================

def get_default_value_for_type(param_type: str, is_simple: bool) -> Any:
    """Retourne une valeur par défaut selon le type du paramètre"""
    if not is_simple:
        return None  # Types complexes non supportés dans les tests simples
    
    param_type_lower = param_type.lower()
    
    # Types numériques
    if any(t in param_type_lower for t in ['int', 'int32', 'int64', 'short', 'long', 'byte']):
        return DEFAULT_INT_VALUE
    
    # Types décimaux
    if any(t in param_type_lower for t in ['float', 'double', 'decimal']):
        return DEFAULT_FLOAT_VALUE
    
    # Types booléens
    if 'bool' in param_type_lower:
        return DEFAULT_BOOL_VALUE
    
    # Types string ou autres
    return DEFAULT_STRING_VALUE


def build_request_params(parameters: List[Dict]) -> Dict[str, Any]:
    """Construit les paramètres de la requête"""
    params = {}
    for param in parameters:
        param_name = param.get("Name", "")
        param_type = param.get("Type", "String")
        is_simple = param.get("IsSimpleType", True)
        
        value = get_default_value_for_type(param_type, is_simple)
        if value is not None:
            params[param_name] = value
    
    return params


def should_skip_endpoint(parameters: List[Dict]) -> tuple[bool, str]:
    """Vérifie si l'endpoint doit être ignoré basé sur les noms de paramètres"""
    excluded_param_names = ["searchData"]  # Liste des paramètres à exclure
    
    for param in parameters:
        param_name = param.get("Name", "")
        if param_name in excluded_param_names:
            return True, f"Paramètre '{param_name}' trouvé - endpoint ignoré"
    
    return False, ""


def test_endpoint(endpoint: Dict) -> Dict[str, Any]:
    """Teste un endpoint et retourne les résultats"""
    route = endpoint.get("Route", "")
    http_verbs = endpoint.get("HttpVerbs", ["GET"])
    parameters = endpoint.get("Parameters", [])
    
    # Construire l'URL complète
    url = f"{BASE_URL}{route}"
    
    # Vérifier si l'endpoint doit être ignoré
    should_skip, skip_reason = should_skip_endpoint(parameters)
    if should_skip:
        return {
            "endpoint": route,
            "controller": endpoint.get("Controller", ""),
            "action": endpoint.get("Action", ""),
            "http_method": http_verbs[0] if http_verbs else "GET",
            "parameters": [p.get("Name") for p in parameters],
            "timestamp": datetime.now().isoformat(),
            "success": None,
            "status_code": None,
            "response_time_ms": None,
            "error": None,
            "response_data": None,
            "skipped": True,
            "skip_reason": skip_reason
        }
    
    # Construire les paramètres
    params = build_request_params(parameters)
    
    # Préparer le résultat
    result = {
        "endpoint": route,
        "controller": endpoint.get("Controller", ""),
        "action": endpoint.get("Action", ""),
        "http_method": http_verbs[0] if http_verbs else "GET",
        "parameters": params,
        "timestamp": datetime.now().isoformat(),
        "success": False,
        "status_code": None,
        "response_time_ms": None,
        "error": None,
        "response_data": None,
        "skipped": False
    }
    
    try:
        # Choisir le premier verbe HTTP
        http_method = http_verbs[0] if http_verbs else "GET"
        
        # Mesurer le temps de réponse
        start_time = time.time()
        
        # Effectuer la requête selon le verbe HTTP
        if http_method.upper() == "GET":
            response = requests.get(
                url,
                params=params,
                headers=HEADERS,
                cookies=COOKIES,
                verify=True,  # Vérification SSL activée pour Azure
                timeout=60
            )
        elif http_method.upper() == "POST":
            response = requests.post(
                url,
                data=params,
                headers=HEADERS,
                cookies=COOKIES,
                verify=True,
                timeout=60
            )
        elif http_method.upper() == "PUT":
            response = requests.put(
                url,
                data=params,
                headers=HEADERS,
                cookies=COOKIES,
                verify=True,
                timeout=60
            )
        elif http_method.upper() == "DELETE":
            response = requests.delete(
                url,
                params=params,
                headers=HEADERS,
                cookies=COOKIES,
                verify=True,
                timeout=60
            )
        else:
            raise ValueError(f"Méthode HTTP non supportée: {http_method}")
        
        end_time = time.time()
        response_time = (end_time - start_time) * 1000  # Convertir en millisecondes
        
        # Enregistrer les résultats
        result["success"] = response.status_code < 400
        result["status_code"] = response.status_code
        result["response_time_ms"] = round(response_time, 2)
        
        # Stocker uniquement les réponses d'erreur (4xx, 5xx)
        if response.status_code >= 400:
            try:
                result["response_data"] = response.json()
            except:
                result["response_data"] = response.text[:500]  # Limiter la taille
        
    except requests.exceptions.Timeout:
        result["error"] = "Timeout - Le serveur n'a pas répondu dans les délais"
    except requests.exceptions.ConnectionError:
        result["error"] = "Erreur de connexion - Impossible de joindre le serveur"
    except Exception as e:
        result["error"] = f"Erreur inattendue: {str(e)}"
    
    return result


def main():
    """Fonction principale"""
    # Parser les arguments de ligne de commande
    parser = argparse.ArgumentParser(description='Test des endpoints ASP.NET')
    parser.add_argument('--start', type=int, default=0, 
                        help='Index de début (défaut: 0)')
    parser.add_argument('--end', type=int, default=None, 
                        help='Index de fin (défaut: tous les endpoints)')
    parser.add_argument('--limit', type=int, default=None, 
                        help='Nombre maximum d\'endpoints à tester')
    parser.add_argument('--controller', type=str, default=None, 
                        help='Filtrer par nom de controller (ex: "ApiScan")')
    parser.add_argument('--stop-on-error', action='store_true', 
                        help='Arrêter l\'exécution à la première erreur')
    parser.add_argument('--input', type=str, default=INPUT_JSON_FILE, 
                        help=f'Fichier JSON d\'entrée (défaut: {INPUT_JSON_FILE})')
    
    args = parser.parse_args()
    
    print(f"=== Test des endpoints ASP.NET ===")
    print(f"Base URL: {BASE_URL}")
    print(f"Fichier d'entrée: {args.input}")
    print()
    
    # Charger les endpoints depuis le fichier JSON
    try:
        with open(args.input, 'r', encoding='utf-8') as f:
            endpoints = json.load(f)
        print(f"✓ {len(endpoints)} endpoints chargés")
    except FileNotFoundError:
        print(f"✗ Erreur: Le fichier '{args.input}' n'existe pas")
        return
    except json.JSONDecodeError as e:
        print(f"✗ Erreur: Le fichier JSON est invalide - {e}")
        return
    
    # Filtrer par controller si spécifié
    if args.controller:
        endpoints = [ep for ep in endpoints if ep.get("Controller", "").lower() == args.controller.lower()]
        print(f"✓ Filtré par controller '{args.controller}': {len(endpoints)} endpoints")
    
    # Appliquer les limites start/end/limit
    start_idx = args.start
    if args.end is not None:
        end_idx = min(args.end, len(endpoints))
    elif args.limit is not None:
        end_idx = min(start_idx + args.limit, len(endpoints))
    else:
        end_idx = len(endpoints)
    
    endpoints_to_test = endpoints[start_idx:end_idx]
    
    print(f"✓ Test de {len(endpoints_to_test)} endpoints (index {start_idx} à {end_idx-1})")
    if args.stop_on_error:
        print("⚠ Mode 'stop-on-error' activé")
    
    output_file = f"test_results_{start_idx}_{end_idx}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    print(f"Fichier de sortie: {output_file}")
    
    # Tester chaque endpoint
    results = []
    print(f"\nDébut des tests...\n")
    
    for i, endpoint in enumerate(endpoints_to_test, start_idx + 1):
        route = endpoint.get("Route", "N/A")
        print(f"[{i}/{start_idx + len(endpoints_to_test)}] Test de {route}...", end=" ")
        
        result = test_endpoint(endpoint)
        results.append(result)
        
        if result.get("skipped"):
            print(f"⊘ IGNORÉ: {result.get('skip_reason', '')}")
        elif result["success"]:
            print(f"✓ OK ({result['status_code']}) - {result['response_time_ms']}ms")
        else:
            if result["error"]:
                print(f"✗ ERREUR: {result['error']}")
            else:
                print(f"✗ ÉCHEC ({result['status_code']}) - {result['response_time_ms']}ms")
            
            # Arrêter si l'option stop-on-error est activée
            if args.stop_on_error and not result.get("skipped"):
                print(f"\n⚠ Arrêt suite à une erreur (--stop-on-error activé)")
                break
    
    # Sauvegarder les résultats
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\n✓ Résultats sauvegardés dans '{output_file}'")
    except Exception as e:
        print(f"\n✗ Erreur lors de la sauvegarde: {e}")
    
    # Statistiques finales
    total = len(results)
    success = sum(1 for r in results if r["success"])
    skipped = sum(1 for r in results if r.get("skipped"))
    failed = total - success - skipped
    
    print(f"\n=== Résumé ===")
    print(f"Total: {total}")
    print(f"Succès: {success} ({success/total*100:.1f}%)")
    print(f"Échecs: {failed} ({failed/total*100:.1f}%)")
    print(f"Ignorés: {skipped} ({skipped/total*100:.1f}%)")
    
    if results:
        tested_results = [r for r in results if r["response_time_ms"]]
        if tested_results:
            avg_time = sum(r["response_time_ms"] for r in tested_results) / len(tested_results)
            print(f"Temps moyen de réponse: {avg_time:.2f}ms")


if __name__ == "__main__":
    main()