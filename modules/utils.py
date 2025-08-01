import requests


def make_request(target_url, method='POST', params=None, data=None, auth=None, cookies=None, timeout=10):
    """
    A centralized function to handle HTTP requests, supporting both GET and POST.

    This wrapper simplifies the process of making requests by providing a single
    interface and includes basic error handling.


    :param target_url: The URL to send the request to.
    :param method: The HTTP method to use ('GET' or 'POST').
    :param params: A dictionary of URL parameters for GET requests.
    :param data: A dictionary of form data for POST requests.
    :param auth: A tuple for basic authentication (username, password).
    :param cookies: A dictionary of cookies to include in the request.
    :param timeout: The request timeout in seconds.
    :return: A requests.Response object on success, "TIMEOUT" on timeout, or None on other errors.
    """
    try:
        if method.upper() == 'GET':
            # For GET requests, parameters are sent in the 'params' argument
            response = requests.get(target_url, params=params, auth=auth, cookies=cookies, timeout=timeout)
        else:
            # For POST requests, parameters are sent in the 'data' argument
            response = requests.post(target_url, data=data, auth=auth, cookies=cookies, timeout=timeout)

        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
        return response
    except requests.exceptions.Timeout:
        # Handle cases where the request takes too long.
        return "TIMEOUT"
    except requests.exceptions.RequestException as e:
        # Handle other network-related errors.
        print(f"[-] An error occurred: {e}")
        return None

