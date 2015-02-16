# InvokeTwitterAPIs
PowerShell Module to Invoke the Twitter REST APIs and Streaming APIs v1.1. 

#Before you begin...

You must obtain a Twitter API key, API secret, access token and access token secretmand create a hash with this info that will be passed to the commands

$OAuth = @{'ApiKey' = 'xxxxxxxxxxxxxxxxxxxx'; 
	     'ApiSecret' = 'xxxxxxxxxxxxxxxxx';
 	     'AccessToken' = 'xxxxxxxxxxxxxxx';
 	     'AccessTokenSecret' = 'xxxxxxxxxx'} 


https://twittercommunity.com/t/how-to-get-my-api-key/7033


#Commands:

#Invoke-TwitterRestMethod                                          

Provides a command to call any Twitter REST API.  https://dev.twitter.com/rest/public
Pass the desired resource url, list of parameters [key=value], specify the HTTP verb, your $OAuth hash 


ex. 
Invoke-TwitterRestMethod -ResourceURL 'https://api.twitter.com/1.1/direct_messages/new.json' -RestVerb 'POST' 
-Parameters @{'text' = 'hello, there'; 'screen_name' = 'ruminaterumi' } -OAuthSettings $OAuth 



The response will be converted into a ps object


#Invoke-ReadFromTwitterStream                                                               


Provides a command to access any of the Twitter Streaming APIs
Pass the streaming api url, the path to a file where the responses will be written, the parameters, the http verb, your $OAuth hash, and the number of minutes to read from the stream (or attempt to) -1 is infinite

ex.
Invoke-ReadFromTwitterStream -OAuthSettings $OAuth -OutFilePath 'C:\books\foo.txt' -ResourceURL 'https://stream.twitter.com/1.1/statuses/filter.json' -RestVerb 'POST' -Parameters @{'track' = 'foo'} -MinsToCollectStream 1



#Invoke-TwitterMediaUpload  

Provides a command to upload media to Twitter. The media id returned can be used to post a status or tweet with that image.
This takes the url to upload media, the path to image [jpeg, gif, or png], http verb [POST]
ex.

$mediaId = Invoke-TwitterMEdiaUpload -MediaFilePath 'C:\Books\pic.png' -ResourceURL 'https://upload.twitter.com/1.1/media/upload.json' -OAuthSettings $OAuth 

Invoke-TwitterRestMethod -ResourceURL 'https://api.twitter.com/1.1/statuses/update.json' -RestVerb 'POST' -Parameters @{'status'='posted pic'; 'media_ids' = $mediaId } -OAuthSettings $OAuth 

#Installation

To install this module use this PowerShell command:

iex (New-Object Net.WebClient).DownloadString("https://gist.githubusercontent.com/eshakaya/834f9131cd33176a96ff/raw/dda2727f9b5cb6e1b7d9c650515caf61199c07b5/Install.ps1")
