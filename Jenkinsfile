pipeline {
  agent any
  stages {
    stage('Download .NET') {
      steps {
        sh '''if [ ! -f $dotnetPath/dotnet ]; then
  mkdir -p $dotnetPath & wget -q -O- $dotnetUrl | tar -xz -C $dotnetPath
fi'''
      }
    }
    stage('Build') {
      steps {
        sh '$dotnetPath/dotnet publish Surfus.Shell -c Release -o ../artifacts'
      }
    }
    stage('Archive') {
      steps {
        dir(path: 'archive') {
          archiveArtifacts(artifacts: '*', onlyIfSuccessful: true)
        }

      }
    }
  }
  environment {
    dotnetPath = '/tmp/dotnet-sdk-2.1.302-linux-x64-take2'
    dotnetUrl = 'https://download.microsoft.com/download/4/0/9/40920432-3302-47a8-b13c-bbc4848ad114/dotnet-sdk-2.1.302-linux-x64.tar.gz'
  }
}