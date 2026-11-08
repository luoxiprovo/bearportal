/** Renew the managed session before sending a customer form; never replay a submitted mutation. */
export const CUSTOMER_SESSION_SCRIPT = String.raw`(function(){
  document.querySelectorAll('form[method="post"][action^="/portal/"]').forEach(function(form){
    var pending=false,ready=false;
    form.addEventListener('submit',async function(event){
      if(ready)return;
      event.preventDefault();
      if(pending)return;
      pending=true;
      var submitter=event.submitter,error=form.querySelector('[data-session-error]');
      if(error)error.remove();
      form.setAttribute('aria-busy','true');
      try{
        var response=await fetch('/auth/options',{cache:'no-store'}),options=await response.json();
        if(!response.ok)throw Error('We couldn’t check your sign-in. Try again in a moment.');
        if(options.configured){
          if(!options.hasRefreshSession)throw Error('Your sign-in has expired. Sign in again before submitting. Your form is still here.');
          var renewed=await fetch('/auth/refresh',{method:'POST',headers:{'content-type':'application/json','x-bearportal-auth-csrf':options.csrf},body:'{}',cache:'no-store'});
          if(!renewed.ok)throw Error(renewed.status===401?'Your sign-in has expired. Sign in again before submitting. Your form is still here.':'We couldn’t renew your sign-in. Try again in a moment.');
        }
        ready=true;
        try{form.requestSubmit(submitter||undefined)}finally{ready=false}
      }catch(failure){
        error=document.createElement('p');error.dataset.sessionError='';error.className='notice error';error.setAttribute('role','alert');error.textContent=failure.message||'We couldn’t check your sign-in. Try again.';
        var link=document.createElement('a');link.href='/login';link.target='_blank';link.rel='noopener noreferrer';link.textContent=' Sign in in a new tab';error.appendChild(link);form.appendChild(error);
      }finally{pending=false;form.removeAttribute('aria-busy')}
    });
  });
})();`;
