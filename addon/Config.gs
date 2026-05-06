var APP_NAME = 'MailWatch Tower';
var BACKEND_BASE_URL_PROPERTY = 'BACKEND_BASE_URL';
var ADDON_SHARED_SECRET_PROPERTY = 'ADDON_SHARED_SECRET';
var FALLBACK_BACKEND_BASE_URL = 'https://mailwatch-tower.onrender.com';
var API_TIMEOUT_MS = 15000;
var MAX_BODY_CHARS = 20000;
var MAX_URLS = 30;
var MAX_ATTACHMENTS = 20;
var ANALYSIS_CACHE_SECONDS = 300;
var PENDING_FEEDBACK_CACHE_SECONDS = 900;
var SELECTED_FEEDBACK_COLOR = '#0B3D91';

var CATEGORY_ORDER = [
  'sender_auth',
  'links',
  'attachments',
  'content',
  'external_intel',
  'user_feedback',
];

var CATEGORY_LABELS = {
  sender_auth: 'Sender & Authentication',
  links: 'Links & URLs',
  attachments: 'Attachments',
  content: 'Content & Social Engineering',
  external_intel: 'External Intelligence',
  user_feedback: 'User Feedback / Overrides',
};

var CATEGORY_COLORS = {
  sender_auth: '#A67C52',
  links: '#0B3D91',
  attachments: '#E91E63',
  content: '#000000',
  external_intel: '#4A4A4A',
  user_feedback: '#4A4A4A',
};

var SIGNAL_LEGEND_ITEMS = [
  { label: 'Sender identity', color: '#A67C52' },
  { label: 'Links and URLs', color: '#0B3D91' },
  { label: 'Attachments', color: '#E91E63' },
  { label: 'Content / social engineering', color: '#000000' },
  { label: 'Headers / authentication', color: '#6A1B9A' },
  { label: 'Metadata / context', color: '#4A4A4A' },
];

var VERDICT_COLORS = {
  Safe: '#188038',
  'Low Risk': '#4FC3F7',
  Suspicious: '#FBC02D',
  'High Risk': '#F57C00',
  Dangerous: '#D93025',
};

function getBackendBaseUrl() {
  var configured = PropertiesService.getScriptProperties().getProperty(BACKEND_BASE_URL_PROPERTY);
  return trimTrailingSlash_(configured || FALLBACK_BACKEND_BASE_URL);
}

function getAddonSharedSecret() {
  return PropertiesService.getScriptProperties().getProperty(ADDON_SHARED_SECRET_PROPERTY);
}

function trimTrailingSlash_(value) {
  return String(value || '').replace(/\/+$/, '');
}
