#asocApiKeyId='xxxxxxxxxxxxx'
#asocApiKeySecret='xxxxxxxxxxxxx'
#serviceUrl='xxxxxxxxxxxxx'
#maxCriticalIssuesAllowed=1
#maxHighIssuesAllowed=20
#maxMediumIssuesAllowed=50

scanId=$(cat scanId.txt)

asocToken=$(curl -k -s -X POST --header 'Content-Type:application/json' --header 'Accept:application/json' -d '{"KeyId":"'"$asocApiKeyId"'","KeySecret":"'"$asocApiKeySecret"'"}' "https://$serviceUrl/api/v4/Account/ApiKeyLogin" | grep -oP '(?<="Token":\ ")[^"]*')

if [ -z "$asocToken" ]; then
    echo "The token variable is empty. Check the authentication process.";
    exit 1
fi

scanTech=$(cat scanTech.txt)
if [[ $scanTech == 'Sast' ]]; then
    curl -k -s -X GET "https://cloud.appscan.com/api/v4/Scans/Sast/$scanId" -H 'accept:application/json' -H "Authorization:Bearer $asocToken" > scanResult.txt
elif [[ $scanTech == 'Dast' ]]; then
    curl -k -s -X GET "https://cloud.appscan.com/api/v4/Scans/Dast/$scanId" -H 'accept:application/json' -H "Authorization:Bearer $asocToken" > scanResult.txt
elif [[ $scanTech == 'Sca' ]]; then
    curl -k -s -X GET "https://cloud.appscan.com/api/v4/Scans/Sca/$scanId" -H 'accept:application/json' -H "Authorization:Bearer $asocToken" > scanResult.txt
else
    echo "Scan technology not identified."
    exit 1
fi

criticalIssues=$(cat scanResult.txt | jq -r '.LatestExecution | {NCriticalIssues} | join(" ")')
highIssues=$(cat scanResult.txt | jq -r '.LatestExecution | {NHighIssues} | join(" ")')
mediumIssues=$(cat scanResult.txt | jq -r '.LatestExecution | {NMediumIssues} | join(" ")')
lowIssues=$(cat scanResult.txt | jq -r '.LatestExecution | {NLowIssues} | join(" ")')
totalIssues=$(cat scanResult.txt | jq -r '.LatestExecution | {NIssuesFound} | join(" ")')
echo "There are $criticalIssues critical issues, $highIssues high issues, $mediumIssues medium issues, and $lowIssues low issues"

if [[ "$criticalIssues" -gt "$maxCriticalIssuesAllowed" ]]; then
    echo "The company policy permits less than $maxCriticalIssuesAllowed critical issues"
    echo "Security Gate build failed"
    exit 1
elif [[ "$highIssues" -gt "$maxHighIssuesAllowed" ]]; then
    echo "The company policy permits less than $maxHighIssuesAllowed high issues"
    echo "Security Gate build failed"
    exit 1
elif [[ "$mediumIssues" -gt "$maxMediumIssuesAllowed" ]]; then
    echo "The company policy permits less than $maxMediumIssuesAllowed medium issues"
    echo "Security Gate build failed"
    exit 1
fi
echo "The company policy permits less than $maxCriticalIssuesAllowed critical issues, $maxHighIssuesAllowed high issues, and $maxMediumIssuesAllowed medium issues"
echo "Security Gate passed"

curl -k -s -X 'GET' "https://$serviceUrl/api/v4/Account/Logout" -H 'accept: */*' -H "Authorization: Bearer $asocToken"
