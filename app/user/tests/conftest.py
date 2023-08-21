def api_client_with_credentials(token: str, api_client):
    """
    This function sets the HTTP_AUTHORIZATION header in the given API client with the provided token.
    
    Args:
        token (str): The authentication token to be included in the authorization header.
        api_client: The API client instance on which the authorization header will be set.
        
    Returns:
        api_client: The modified API client instance with the authorization header set.
    """
    return api_client.credentials(HTTP_AUTHORIZATION="Bearer " + token)
