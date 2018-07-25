pipeline {
  agent any
  stages {
    stage('Download .NET') {
      steps {
        sh '''wget -nvc https://download.microsoft.com/download/4/0/9/40920432-3302-47a8-b13c-bbc4848ad114/dotnet-sdk-2.1.302-linux-x64.tar.gz
'''
        sh 'tar xfk dotnet-sdk-2.1.302-linux-x64.tar.gz'
      }
    }
    stage('Build') {
      steps {
        sh 'DOTNET_SKIP_FIRST_TIME_EXPERIENCE=true ./dotnet publish Surfus.Shell -c Release -o ../artifacts'
        archiveArtifacts(artifacts: 'artifacts', onlyIfSuccessful: true)
      }
    }
  }
}