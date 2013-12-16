navigator.id.beginProvisioning(function(email, cert_duration) {
  $.get('/api/loggedin')
    .success(function(r) {
      navigator.id.genKeyPair(function(pubkey) {
        // TODO: find out whether or not this is needed
        if (typeof(pubkey) == "string") {
          pubkey = JSON.parse(pubkey);
        }

        $.ajax({
          url: '/api/cert_key',
          data: JSON.stringify({
            pubkey: pubkey,
            duration: cert_duration
          }),
          type: 'POST',
          headers: { "Content-Type": 'application/json' },
          dataType: 'json',
          success: function(r) {
            navigator.id.registerCertificate(r.cert);
          },
          error: function() {
            navigator.id.raiseProvisioningFailure("couldn't certify key");
          }
        });
      });
    })
    .error(function() {
      navigator.id.raiseProvisioningFailure('user is not authenticated');
    });
});
