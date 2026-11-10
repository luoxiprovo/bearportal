/** Refresh inventory even when a successful mutation returns the current page URL. */
export const INVENTORY_FORM_SCRIPT = `
  var notice=document.querySelector('.inventory-notice');
  if(notice)notice.scrollIntoView({block:'center'});
  document.querySelectorAll('form.inventory-form').forEach(function(form){
    var pending=false;
    form.addEventListener('submit',async function(event){
      event.preventDefault();
      if(pending)return;
      pending=true;
      var submit=event.submitter||form.querySelector('[type=submit]'),error=form.querySelector('.form-error');
      if(error)error.hidden=true;
      var originalLabel=submit&&submit.textContent;
      if(submit){submit.disabled=true;submit.textContent=new URL(form.action).pathname==='/operator/inventory/servers'?'Checking SSH access…':'Saving…'}
      form.setAttribute('aria-busy','true');
      var navigating=false;
      try{
        var response=await fetch(form.action,{method:'POST',headers:{accept:'application/json'},body:new URLSearchParams(new FormData(form))});
        var result=await response.json();
        if(!response.ok)throw new Error(result.error&&result.error.message||'The inventory change could not be saved.');
        if(!result.redirect)throw new Error('The server did not return an inventory page. Refresh to check whether your change was saved.');
        var destination=new URL(result.redirect,location.href);
        var dialog=form.closest('dialog');
        if(dialog)dialog.close();
        if(destination.origin===location.origin&&destination.pathname===location.pathname&&destination.search===location.search){
          location.reload();
        }else{
          location.assign(destination.href);
        }
        navigating=true;
      }catch(failure){
        if(error){error.textContent=failure.message||'Could not reach BearPortal. Please try again.';error.hidden=false;error.focus()}
      }finally{
        if(!navigating){pending=false;form.removeAttribute('aria-busy');if(submit){submit.disabled=false;submit.textContent=originalLabel}}
      }
    });
  });
`;
