$(document).ready(function() {
  navigator.id.beginAuthentication(function(email) {
    navigator.id.completeAuthentication();
    // TODO: navigator.id.raiseAuthenticationFailure("user canceled authentication");
  });
});
