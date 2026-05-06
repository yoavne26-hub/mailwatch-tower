/**
 * Backend API client for MailWatch Tower.
 */

function analyzeEmail(payload) {
  return callBackend('/analyze', 'post', payload);
}

function submitFeedbackToBackend(payload) {
  return callBackend('/feedback', 'post', payload);
}

function checkBackendHealth() {
  return callBackend('/health', 'get', null);
}

function callBackend(path, method, payload) {
  var url = getBackendBaseUrl() + path;
  var options = {
    method: method,
    muteHttpExceptions: true,
    headers: buildBackendHeaders_(),
  };

  if (payload !== null && payload !== undefined) {
    options.contentType = 'application/json';
    options.payload = JSON.stringify(payload);
  }

  var response;
  try {
    response = UrlFetchApp.fetch(url, options);
  } catch (error) {
    Logger.log('Backend request failed for ' + path + ': ' + sanitizeLogText_(error && error.message ? error.message : String(error)));
    throw new Error('Backend service is unreachable. Check BACKEND_BASE_URL / tunnel URL and backend /health.');
  }

  return parseJsonResponse_(response, method.toUpperCase() + ' ' + path);
}

function checkBackendHealthAction(e) {
  try {
    var healthResponse = checkBackendHealth();
    return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().pushCard(buildHealthCard(healthResponse)))
      .build();
  } catch (error) {
    return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().pushCard(
        buildErrorCard('Backend health check failed', error && error.message ? error.message : String(error))
      ))
      .build();
  }
}

function parseJsonResponse_(response, operationName) {
  var statusCode = response.getResponseCode();
  var responseText = response.getContentText() || '';
  var parsed;

  try {
    parsed = responseText ? JSON.parse(responseText) : {};
  } catch (error) {
    throw new Error(operationName + ' returned a response that was not valid JSON.');
  }

  if (statusCode < 200 || statusCode >= 300) {
    throw new Error(operationName + ' failed with status ' + statusCode + ': ' + truncateText(responseText, 500));
  }

  return parsed;
}

function buildBackendHeaders_() {
  var headers = {};
  var sharedSecret = getAddonSharedSecret();
  if (sharedSecret) {
    headers['X-MailWatch-Addon-Secret'] = sharedSecret;
  }
  return headers;
}

function sanitizeLogText_(value) {
  return String(value || '').slice(0, 300);
}
