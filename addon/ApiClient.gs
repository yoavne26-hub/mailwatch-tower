/**
 * Backend API client for MailWatch Tower.
 */

function analyzeEmail(payload) {
  var response = UrlFetchApp.fetch(BACKEND_BASE_URL + '/analyze', {
    method: 'post',
    contentType: 'application/json',
    payload: JSON.stringify(payload),
    muteHttpExceptions: true,
  });

  return parseJsonResponse_(response, 'POST /analyze');
}

function checkBackendHealth() {
  var response = UrlFetchApp.fetch(BACKEND_BASE_URL + '/health', {
    method: 'get',
    muteHttpExceptions: true,
  });

  return parseJsonResponse_(response, 'GET /health');
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
    throw new Error(operationName + ' returned non-JSON response: ' + truncateText(responseText, 500));
  }

  if (statusCode < 200 || statusCode >= 300) {
    throw new Error(operationName + ' failed with status ' + statusCode + ': ' + truncateText(responseText, 500));
  }

  return parsed;
}
