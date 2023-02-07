/* #################################################################### 
                Inital Sync
   ####################################################################  */

async function getData(url) {
	try {
		let res = await fetch(url);
		return await res.json();
	} catch (error) {
		console.log(error);
	}
}


/* #################################################################### 
                DHCP Full Vendor Details
   ####################################################################  */
async function renderIOTFullDetails()
{
    let data = await getData('/api/iotdevicesfulldetails');
	/* If there is an IP to show, remove the spinner */
    if (!(JSON.stringify(data)=='{}'))
    {
        let html = ``;
        html = html + 	`
                          <table id="datatable" class="table table-striped">
                          <thead>
                             <tr>
                                <th>IP Address</th>
                                 <th>MAC Address</th>
                                 <th>Vendor</th>
                             </tr>
                          </thead>
                          <tr>
                          `
        for (entry in data)
        {
            for (split in entry)
            {
                if (data[entry][split] != null)
                {
                    html = html + 	`

                                          <td>${data[entry][split]}</td>
                                    `;
                }
            }
        }
        html = html + 	`
                        </tr>
                         </table>
                         `

        /* Make the home screen show the table */
        jQuery("#spinnernotyetloaded").addClass('d-none');
        jQuery("#header").removeClass('d-none');
        let container = document.querySelector('.iotdevices');
        container.innerHTML = html;
    }
    else
    {
        jQuery("#spinnernotyetloaded").removeClass('d-none');
        jQuery("#header").addClass('d-none');
        let html = ``
        let container = document.querySelector('.iotdevices');
        container.innerHTML = html;
    }
	setTimeout(renderIOTFullDetails, 1000);
	console.log(data);
}

/* ####################################################################
                DHCP IP Addresses
   ####################################################################  */
async function renderIOTIPs()
{
    let data = await getData('/api/iotdevices');
	/* If there is an IP to show, remove the spinner */
    if (data !="")
    {
        /* Make the home screen show the table */
        jQuery("#spinnernotyetloaded").addClass('d-none');
        jQuery("#header").removeClass('d-none');
        let html = data.data
        let container = document.querySelector('.iotdevices');
        container.innerHTML = html;
    }
    else
    {
        jQuery("#spinnernotyetloaded").removeClass('d-none');
        jQuery("#header").addClass('d-none');
        let html = ``
        let container = document.querySelector('.iotdevices');
        container.innerHTML = html;
    }
	setTimeout(renderIOTIPs, 1000);
	console.log(data);
}

/* #################################################################### */

/* #################################################################### 
               DNS Names Seen
   ####################################################################  */

async function renderIOTDNSNames() 
{
    let data = await getData('/api/dnsentries');
    let html = ``;
    for (entry in data) 
    {
        console.log(data[entry]);
        html = html + 	`
                            <tr>
                              <td>${data[entry]}</td>
                            </tr>
                        `;
    }
    let container = document.querySelector('.data');
    container.innerHTML = html;
    setTimeout(renderIOTDNSNames, 3000);
}
/* #################################################################### */

/* ####################################################################
               mDNS Names Seen
   ####################################################################  */

async function renderIOTmDNSNames()
{
    let data = await getData('/api/mdnsentries');
    let html = ``;
    for (entry in data)
    {
        console.log(data[entry]);
        html = html + 	`
                            <tr>
                              <td>${data[entry]}</td>
                            </tr>
                        `;
    }
    let container = document.querySelector('.data');
    container.innerHTML = html;
    setTimeout(renderIOTmDNSNames, 3000);
}
/* #################################################################### */

/* ####################################################################
               DNS Names Seen
   ####################################################################  */

async function renderIOTSNIs()
{
    let data = await getData('/api/snientries');
    let html = ``;
    for (entry in data)
    {
        console.log(data[entry]);
        html = html + 	`
                            <tr>
                              <td>${data[entry]}</td>
                            </tr>
                        `;
    }
    let container = document.querySelector('.data');
    container.innerHTML = html;
    setTimeout(renderIOTSNIs, 3000);
}
/* #################################################################### */

/* ####################################################################
               IOT Conversations
   ####################################################################  */

async function renderIOTConversations()
{
    let data = await getData('/api/conversations');
    let html = ``;
    for (var protocol in data)
    {
        for (var conversation in data[protocol])
        {
            console.log(data[conversation]);
            html = html + 	`
                            <tr>
                            `;
            for (var part in data[protocol][conversation])
            {
                html = html + `
                              <td>${data[protocol][conversation][part]}</td>
                              `;
           }
            html = html + 	`
                            </tr>
                        `;
        }

    }
    let container = document.querySelector('.data');
    container.innerHTML = html;
    setTimeout(renderIOTConversations, 3000);
}
/* #################################################################### */

/* ####################################################################
              Cipher Suites
   ####################################################################  */

async function renderCipherSuitesOffered()
{
    let data = await getData('/api/ciphersuites');
    let html = ``;
    for (var conversation in data)
    {
        console.log(data[conversation]);
        html = html + 	`
                        <tr>
                        `;
        for (var part in data[conversation])
        {
            html = html + `
                          <td>${data[conversation][part]}</td>
                          `;
       }
        html = html + 	`
                        </tr>
                    `;
    }
    let container = document.querySelector('.data');
    container.innerHTML = html;
    setTimeout(renderCipherSuitesOffered, 3000);
}
/* #################################################################### */

/* #################################################################### 
               NMAP
   ####################################################################  */
   
async function checkNMAP() {
	try 
	{
        let data = await getData('api/nmapstatus');
        let html = ``;
        container = document.getElementById('nmapStatus');
        if (data =="running")
        {
            html = `<a id="nmapStatus" class="btn btn-warning" role="button">Currently Running</a>`        
            container.outerHTML = html;        
        }
        else if (data =="finished")
        {
            html = `<a id="nmapStatus" class="btn btn-success" role="button">Finished</a>`        
            container.outerHTML = html;        
        }
        else
        {
            html = `<a id="nmapStatus" class="btn btn-error" role="button">Starting</a>`        
            container.outerHTML = html;        
        }        
        console.log(data)
    } catch (error) {
    console.log(error);     
    } finally {        
		setTimeout(checkNMAP, 3000);
    }
}   

async function renderNMAP() {
	try 
	{
        let data = await getData('api/nmap');
        let html = ``;
        for (entry in data) 
        {
            console.log(data[entry]);
            /* const myArray = data[entry].split(" ");*/
            myArray = data[entry]
            html = html + 	`
                                <tr>
                            `;
            for (split in myArray) 
            {
                html = html + `
                              <td>${myArray[split]}</td>               
                        `;
            }
            html = html + 	`
                                </tr>
                            `;
        }
        let container = document.querySelector('.data');
        container.innerHTML = html;
    } catch (error) {
    console.log(error); 
    } finally {
		setTimeout(renderNMAP, 3000);
    }
}
/* #################################################################### */

/* #################################################################### 
               MiTMProxy
   ####################################################################  */

async function startMITMProxyDefaultMode() {
	try 
	{
       	let container = document.querySelector('.mitmProxyInformUser');
       	html = `<h2>Starting MiTM Proxy, please wait</h2>`
		container.innerHTML = html;
		
        await getData('/api/mitmProxyDefaultMode');
        
       	container = document.getElementById('startMITMProxy');
       	html = `<a id="startMITMProxy" class="btn btn-success" role="button">Attack Running</a>`        
		container.outerHTML = html;
		
       	container = document.querySelector('.mitmProxyInformUser');
       	html = ``
		container.innerHTML = html;
		
		// Hidden table - make it visable
		jQuery("#mitmdtable").removeClass('d-none');

		alert("The IOT device must now be restarted to force new connections, please reboot it and try to use it again")
		
    } 
    catch (error) 
    {
        console.log(error); 
    }
    finally 
    {
		getMiTMProxyConvos();
    }       
}

async function startMITMProxyCloneMode() {
	try 
	{
       	let container = document.querySelector('.mitmProxyInformUser');
       	html = `<h2>Creating Certificate Chains, this can take several mins, please wait</h2>`
		container.innerHTML = html;
		
        await getData('/api/mitmProxyCloneMode');

       	container = document.getElementById('startMITMProxy');
       	html = `<a id="startMITMProxy" class="btn btn-success" role="button">Attack Running</a>`        
		container.outerHTML = html;		
		
        let data = await getData('/api/dnsentries');
        html = `
                     <table width="600">
                      <thead>
                         <tr>
                            <th>MiTM Cloned Certificates Created For</th>
                         </tr>
                      </thead>
                      <tbody>
                    `;
        for (entry in data) 
        {
            console.log(data[entry]);
            html = html + 	`
                                <tr>
                                  <td>${data[entry]}</td>
                                </tr>
                            `;
        }
        html = html + `
                            </tbody>
                              </table>  
                    `;		
       	container = document.querySelector('.mitmProxyInformUser');
		container.innerHTML = html;
		
		// Hidden table - make it visable
		jQuery("#mitmdtable").removeClass('d-none');

		alert("The IOT device must now be restarted to force new connections, please reboot it and try to use it again")
    } 
    catch (error) 
    {
        console.log(error); 
    }
    finally 
    {
		getMiTMProxyConvos();
    }       
}

async function startMITMProxyLetsEncryptCloneMode() {
	try
	{
       	let container = document.querySelector('.mitmProxyInformUser');
       	html = `<h2>Creating Certificate Chains, this can take several mins, please wait</h2>`
		container.innerHTML = html;

        await getData('/api/mitmProxyLetsEncryptCloneMode');

       	container = document.getElementById('startMITMProxy');
       	html = `<a id="startMITMProxy" class="btn btn-success" role="button">Attack Running</a>`
		container.outerHTML = html;

        let data = await getData('/api/dnsentries');
        html = `
                     <table width="600">
                      <thead>
                         <tr>
                            <th>MiTM Cloned Certificates Created For</th>
                         </tr>
                      </thead>
                      <tbody>
                    `;
        for (entry in data)
        {
            console.log(data[entry]);
            html = html + 	`
                                <tr>
                                  <td>${data[entry]}</td>
                                </tr>
                            `;
        }
        html = html + `
                            </tbody>
                              </table>
                    `;
       	container = document.querySelector('.mitmProxyInformUser');
		container.innerHTML = html;

		// Hidden table - make it visable
		jQuery("#mitmdtable").removeClass('d-none');

		alert("The IOT device must now be restarted to force new connections, please reboot it and try to use it again")
    }
    catch (error)
    {
        console.log(error);
    }
    finally
    {
		getMiTMProxyConvos();
    }
}

async function getMiTMProxyConvos() 
{
	try 
	{
        let data = await getData('/api/getMiTMProxyConvos');
        let html = ``;
        for (entry in data) 
        {
            console.log(data[entry]);
            html = html + 	`
                            <tr>
                              <td>${data[entry]}</td>
                            </tr>
                        `;
        }
        let container = document.querySelector('.data');
        container.innerHTML = html;            
    } 
    catch (error) 
    {
        console.log(error); 
    } 
    finally 
    {
		setTimeout(getMiTMProxyConvos, 3000);
    }        
}

async function stopMITMProxyDefaultMode() {
	try 
	{
        await getData('/stopMiTMProxy');
        
       	let container = document.getElementById('startMITMProxy');
       	html = `<a id="startMITMProxy" onClick="startMITMProxyDefaultMode()" class="btn btn-primary" role="button">Start Attack</a>`
		container.outerHTML = html;                    
    }
    catch (error) 
    {
        console.log(error); 
    } 
}

async function stopMITMProxyCloneMode() {
	try 
	{
        await getData('/stopMiTMProxy');
        
       	let container = document.getElementById('startMITMProxy');
       	html = `<a id="startMITMProxy" onClick="startMITMProxyCloneMode()" class="btn btn-primary" role="button">Start Attack</a>`
		container.outerHTML = html;         
		
       	container = document.querySelector('.mitmProxyInformUser');
       	html = ``
		container.innerHTML = html;		
    }
    catch (error) 
    {
        console.log(error); 
    } 
}
