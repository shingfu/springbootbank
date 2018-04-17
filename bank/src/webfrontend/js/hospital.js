// api url
const HOST_URL = "http://127.0.0.1:8086/api/"
const TOKEN_KEY = "jwtToken"

function getJwtToken() {
  return localStorage.getItem(TOKEN_KEY);
}

function setJwtToken(token) {
  localStorage.setItem(TOKEN_KEY, token);
}

function removeJwtToken() {
  localStorage.removeItem(TOKEN_KEY);
}

function createAuthorizationTokenHeader() {
  var token = getJwtToken();
  // console.log(token)
  if (token) {
    return {"Authorization": "Bearer " + token};
  } else {
    return {};
  }
}