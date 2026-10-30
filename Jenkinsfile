pipeline {
    agent any

    triggers {
        pollSCM('* * * * *')
    }

    environment {
        CGO_ENABLED = '0'
    }

    stages {
        stage('Tooling Check') {
            steps {
                sh 'go version'
                sh 'docker --version'
            }
        }

        stage('Unit Tests') {
            steps {
                echo '===> Menjalankan Unit Test Go...'
                dir('CenterServer') {
                    sh 'go test -v ./...'
                }
            }
        }

        stage('Build Docker Images') {
            steps {
                echo '===> Verifikasi Build Docker Image CenterServer...'
                sh 'docker build -t ta-center-siem:ci ./CenterServer'
            }
        }

        stage('build Agent') {
            steps {
                sh '''
                cd Agent && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
                    -ldflags="-s -w" \
                    -o AgentServerOnline \
                    Agent/main.go
                    '''
            }
        }

        stage('deploy agent to server') {
            steps {
               echo '===> Mengirim binary ke server prod-1 dan prod-2...'
                withCredentials([usernamePassword(credentialsId: 'vps-password', usernameVariable: 'USER', passwordVariable: 'PASS')]) {
                    sh '''
                        # 1. Pastikan folder tujuan ada & kirim file ke Prod-1
                        sshpass -p "$PASS" ssh -p 25187 -o StrictHostKeyChecking=no $USER@163.52.135.168 "mkdir -p /home/ubuntu/project"
                        sshpass -p "$PASS" scp -P 25187 -o StrictHostKeyChecking=no \
                            Agent/AgentServerOnline $USER@163.52.135.168:/home/ubuntu/project/
                        sshpass -p "$PASS" ssh -p 25187 -o StrictHostKeyChecking=no $USER@163.52.135.168 "chmod +x /home/ubuntu/project/AgentServerOnline"
                        # 2. Pastikan folder tujuan ada & kirim file ke Prod-2
                        sshpass -p "$PASS" ssh -p 27151 -o StrictHostKeyChecking=no $USER@163.52.135.170 "mkdir -p /home/ubuntu/project"
                        sshpass -p "$PASS" scp -P 27151 -o StrictHostKeyChecking=no \
                            Agent/AgentServerOnline $USER@163.52.135.170:/home/ubuntu/project/
                        sshpass -p "$PASS" ssh -p 27151 -o StrictHostKeyChecking=no $USER@163.52.135.170 "chmod +x /home/ubuntu/project/AgentServerOnline"
                    '''
                }
            }
        }
    }

    post {
        success {
            echo "Build & deploy berhasil"
        }
        failure {
            echo "Pipeline gagal, coba di cek kembali"
        }
        always {
            echo "Pembersihan workspace selesai"
        }
    }
}