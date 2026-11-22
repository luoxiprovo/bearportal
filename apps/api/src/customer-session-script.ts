/** Renew the managed session before sending a customer form; never replay a submitted mutation. */
export const CUSTOMER_SESSION_SCRIPT = String.raw`(function(){
  if(typeof window!=='undefined'){
    function openAccount(){var account=document.getElementById('account');if(account&&location.hash==='#account')account.open=true}
    window.addEventListener('hashchange',openAccount);openAccount();
  }
  async function mountCheckout(form,submitter){
    if(form.dataset.stripeMounted==='true')return;
    var key=form.dataset.stripePublishableKey;
    if(!key||!/^pk_(test|live)_/.test(key))throw Error('Checkout is unavailable. Contact support.');
    if(typeof Stripe!=='function')throw Error('Stripe could not load. Refresh the page and try again.');
    if(submitter)submitter.disabled=true;
    var embedded;
    try{
      var appearance={theme:'stripe',labels:'auto',inputs:'spaced',variables:{borderRadius:'4px',colorBackground:'#ffffff',colorDanger:'#df1b41',colorPrimary:'#0570de',colorSuccess:'#00c853',colorText:'#30313d',fontFamily:'default',fontSizeBase:'16px',spacingUnit:'4px'}};
      var clientSecret=fetch(form.action,{method:'POST',headers:{accept:'application/json'},body:new URLSearchParams(new FormData(form)),cache:'no-store'}).then(async function(response){var result=await response.json();if(!response.ok){var failure=Error(result.error&&result.error.message||'Could not start checkout. Try again.');failure.signInRequired=response.status===401;throw failure}if(!result.client_secret)throw Error('Could not load checkout. Try again.');return result.client_secret});
      var checkout=Stripe(key).initCheckoutFormSdk({clientSecret:clientSecret,appearance:appearance});
      embedded=checkout.createForm({layout:'expanded'});
      embedded.mount('#checkout-form');
      var loaded=await checkout.loadActions();
      if(loaded.type!=='success')throw Error(loaded.error&&loaded.error.message||'Could not load checkout. Try again.');
      var confirming=false;
      embedded.on('confirm',async function(event){
        if(confirming)return;
        confirming=true;
        var error=form.querySelector('[data-checkout-error]');if(error)error.remove();
        try{
          var returnUrl=location.origin+'/portal/billing/return?session_id='+encodeURIComponent(loaded.actions.getSession().id);
          var confirmed=await loaded.actions.confirm({formConfirmEvent:event,returnUrl:returnUrl,redirect:'if_required'});
          if(confirmed.type==='error')throw Error(confirmed.error&&confirmed.error.message||'Could not confirm payment. Try again.');
          if(confirmed.type==='success')location.assign(returnUrl);
        }catch(failure){
          error=document.createElement('p');error.dataset.checkoutError='';error.className='notice error';error.setAttribute('role','alert');error.textContent=failure.message||'Could not confirm payment. Try again.';form.appendChild(error);
        }finally{confirming=false}
      });
      form.dataset.stripeMounted='true';
      if(submitter)submitter.hidden=true;
    }catch(error){if(embedded)embedded.unmount();throw error}
    finally{if(submitter)submitter.disabled=false}
  }
  document.querySelectorAll('form[method="post"][action^="/portal/"]').forEach(function(form){
    var pending=false,ready=false;
    form.addEventListener('submit',async function(event){
      if(ready)return;
      event.preventDefault();
      if(pending)return;
      pending=true;
      var authReady=false,submitter=event.submitter,error=form.querySelector('[data-session-error]');
      if(error)error.remove();
      form.setAttribute('aria-busy','true');
      try{
        var response=await fetch('/auth/options',{cache:'no-store'}),options=await response.json();
        if(!response.ok)throw Error('Could not check your sign-in. Try again.');
        if(options.configured){
          if(!options.hasRefreshSession)throw Error('Session expired. Sign in again, then submit this form.');
          var renewed=await fetch('/auth/refresh',{method:'POST',headers:{'content-type':'application/json','x-bearportal-auth-csrf':options.csrf},body:'{}',cache:'no-store'});
          if(!renewed.ok)throw Error(renewed.status===401?'Session expired. Sign in again, then submit this form.':'Could not refresh your sign-in. Try again.');
        }
        authReady=true;
        if(form.dataset&&form.dataset.stripeCheckout!==undefined){await mountCheckout(form,submitter);return}
        ready=true;
        try{form.requestSubmit(submitter||undefined)}finally{ready=false}
      }catch(failure){
        error=document.createElement('p');error.dataset.sessionError='';error.className='notice error';error.setAttribute('role','alert');error.textContent=failure.message||'We couldn’t check your sign-in. Try again.';
        if(!authReady||failure.signInRequired){var link=document.createElement('a');link.href='/login';link.target='_blank';link.rel='noopener noreferrer';link.textContent=' Sign in in a new tab';error.appendChild(link)}form.appendChild(error);
      }finally{pending=false;form.removeAttribute('aria-busy')}
    });
  });
})();`;
