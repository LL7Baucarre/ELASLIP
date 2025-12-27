"""Request helper functions to reduce duplication across routes."""

from flask import request
from typing import Dict, Any, Tuple, Optional, List


def get_pagination_params(default_page: int = 1, default_per_page: int = 20, max_per_page: int = 100) -> Tuple[int, int]:
    """
    Extract and validate pagination parameters from request.
    
    Args:
        default_page: Default page number (default: 1)
        default_per_page: Default items per page (default: 20)
        max_per_page: Maximum allowed items per page (default: 100)
    
    Returns:
        Tuple of (page, per_page)
    """
    page = request.args.get('page', default_page, type=int)
    per_page = min(request.args.get('per_page', default_per_page, type=int), max_per_page)
    
    # Validate page number
    if page < 1:
        page = 1
    
    return page, per_page


def get_query_param(param_name: str, default: Any = None, param_type: type = str, required: bool = False) -> Any:
    """
    Get and validate a single query parameter.
    
    Args:
        param_name: Name of the parameter
        default: Default value if not provided
        param_type: Type to convert to (str, int, etc.)
        required: Whether the parameter is required
    
    Returns:
        Parameter value or default
    
    Raises:
        ValueError: If required parameter is missing
    """
    value = request.args.get(param_name)
    
    if value is None:
        if required:
            raise ValueError(f"Missing required parameter: {param_name}")
        return default
    
    if param_type == bool:
        return value.lower() in ('true', '1', 'yes')
    
    try:
        return param_type(value)
    except (ValueError, TypeError):
        return default


def get_filters_from_request(allowed_filters: Dict[str, type]) -> Dict[str, Any]:
    """
    Extract and validate multiple filter parameters from request.
    
    Args:
        allowed_filters: Dict mapping parameter names to their types
                        e.g., {'status': str, 'priority': str, 'page': int}
    
    Returns:
        Dict of validated filters (empty dict if none provided)
    """
    filters = {}
    
    for param_name, param_type in allowed_filters.items():
        value = request.args.get(param_name)
        
        if value is None:
            continue
        
        try:
            if param_type == bool:
                filters[param_name] = value.lower() in ('true', '1', 'yes')
            else:
                filters[param_name] = param_type(value)
        except (ValueError, TypeError):
            continue  # Skip invalid values
    
    return filters


def parse_comma_separated_list(param_name: str, strip: bool = True) -> List[str]:
    """
    Parse a comma-separated parameter into a list.
    
    Args:
        param_name: Name of the parameter
        strip: Whether to strip whitespace from items
    
    Returns:
        List of items (empty list if parameter not provided)
    """
    value = request.args.get(param_name, '').strip()
    
    if not value:
        return []
    
    items = value.split(',')
    
    if strip:
        items = [item.strip() for item in items]
    
    return [item for item in items if item]  # Filter empty strings


def get_json_or_form(key: str, default: Any = None) -> Any:
    """
    Get a value from JSON body or form data, preferring JSON.
    
    Args:
        key: Key to retrieve
        default: Default value if not found
    
    Returns:
        Value from request data or default
    """
    if request.is_json:
        return request.get_json().get(key, default)
    
    return request.form.get(key, default)


def build_pagination_response(items: List[Any], total: int, page: int, per_page: int) -> Dict[str, Any]:
    """
    Build a standardized pagination response.
    
    Args:
        items: List of items to include
        total: Total number of items (before pagination)
        page: Current page number
        per_page: Items per page
    
    Returns:
        Dict with pagination metadata
    """
    return {
        'items': items,
        'total': total,
        'page': page,
        'per_page': per_page,
        'pages': (total + per_page - 1) // per_page  # Ceiling division
    }


def build_error_response(message: str, details: Optional[Dict] = None) -> Dict[str, Any]:
    """
    Build a standardized error response.
    
    Args:
        message: Error message
        details: Optional additional error details
    
    Returns:
        Dict with error information
    """
    response = {'error': message}
    if details:
        response.update(details)
    return response

def get_sort_param(default: str = 'created_desc') -> str:
    """
    Get sort parameter from request.
    
    Args:
        default: Default sort parameter
        
    Returns:
        Sort parameter value
    """
    return request.args.get('sort', default)


def get_search_query() -> Optional[str]:
    """
    Get search/query parameter from request.
    
    Returns:
        Search query or None
    """
    return request.args.get('search') or request.args.get('q')


def get_filter_value(filter_name: str, allowed_values: Optional[List[str]] = None) -> Optional[str]:
    """
    Get and validate a filter parameter value.
    
    Args:
        filter_name: Name of the filter parameter
        allowed_values: List of allowed values (validates if provided)
        
    Returns:
        Filter value if valid, None otherwise
    """
    value = request.args.get(filter_name)
    
    if value is None:
        return None
    
    if allowed_values and value not in allowed_values:
        return None
    
    return value


def build_filters_dict(filter_specs: Dict[str, Optional[List[str]]]) -> Dict[str, str]:
    """
    Build filters dictionary from request parameters.
    
    Args:
        filter_specs: Dict of filter_name -> allowed_values (or None for any value)
        
    Returns:
        Dict of validated filters
        
    Example:
        filters = build_filters_dict({
            'status': ['open', 'closed', 'in-progress'],
            'priority': ['low', 'medium', 'high'],
            'search': None  # Allow any value
        })
    """
    filters = {}
    for filter_name, allowed_values in filter_specs.items():
        value = get_filter_value(filter_name, allowed_values)
        if value:
            filters[filter_name] = value
    return filters