
async function login(login_form) {
   fetch('/login', {
	   method: 'POST',
	   headers: { 'Content-Type': 'application/json' },
	   body: JSON.stringify({
		   username: login_form.elements["username"].value,
		   password: login_form.elements["password"].value })
   }).then(response => {
	   if (response.status === 401) {
	   } else {
	      response.json().then(doc => {
	      	document.cookie = "Bearer=" + doc["bearer"] + "; SameSite=Strict; Max-Age=72h";
		window.location.reload();
	      });
	   }
   });
}

async function logout() {
  fetch('/logout').then(res => {
	  document.cookie = "Bearer=; SameSite=Strict; Max-Age=0; expires=Thu, 01 Jan 1970 00:00:01 GMT";
	  window.location.reload();
  });
}


