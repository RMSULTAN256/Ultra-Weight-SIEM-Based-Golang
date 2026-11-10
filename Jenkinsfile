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
                    main.go
                    '''
            }
        }

        stage('deploy agent to server') {
            steps {
               echo '===> Mengirim binary ke server prod-1 dan prod-2...'
                withCredentials([usernamePassword(credentialsId: 'vps-password', usernameVariable: 'USER', passwordVariable: 'PASS')]) {
                    sh '''
                        cd Agent
                        # 1. Deploy ke Prod-1 (Server Baru: user root, path /root/Agent)
                        # Step A: Stop service & pastikan folder config ada
                        sshpass -p "$PASS" ssh -F /dev/null -p 30061 -o StrictHostKeyChecking=no root@31.56.56.50 \
                            "mkdir -p /root/Agent/config && systemctl stop AgentGo"
                        
                        # Step B: Copy binary & file konfigurasi
                        sshpass -p "$PASS" scp -F /dev/null -P 30061 -o StrictHostKeyChecking=no \
                            AgentServerOnline root@31.56.56.50:/root/Agent/
                        sshpass -p "$PASS" scp -F /dev/null -P 30061 -o StrictHostKeyChecking=no \
                            config/log_collector.json root@31.56.56.50:/root/Agent/config/
                        sshpass -p "$PASS" ssh -F /dev/null -p 30061 -o StrictHostKeyChecking=no root@31.56.56.50 \
                            "chmod +x /root/Agent/AgentServerOnline"

                        # Step C: Start service kembali
                        sshpass -p "$PASS" ssh -F /dev/null -p 30061 -o StrictHostKeyChecking=no root@31.56.56.50 \
                            "systemctl start AgentGo"
                        # 2. Deploy ke Prod-2 (Server Lama: 163.52.135.170:27151)

                        # Step A: Stop service & pastikan folder config ada
                        sshpass -p "$PASS" ssh -F /dev/null -p 27151 -o StrictHostKeyChecking=no $USER@163.52.135.170 \
                            "mkdir -p /home/ubuntu/project/config && echo '$PASS' | sudo -S systemctl stop agentGo"

                        # Step B: Copy binary & file konfigurasi
                        sshpass -p "$PASS" scp -F /dev/null -P 27151 -o StrictHostKeyChecking=no \
                            AgentServerOnline $USER@163.52.135.170:/home/ubuntu/project/
                        sshpass -p "$PASS" scp -F /dev/null -P 27151 -o StrictHostKeyChecking=no \
                            config/log_collector.json $USER@163.52.135.170:/home/ubuntu/project/config/
                        sshpass -p "$PASS" ssh -F /dev/null -p 27151 -o StrictHostKeyChecking=no $USER@163.52.135.170 \
                            "chmod +x /home/ubuntu/project/AgentServerOnline"
                            
                        # Step C: Start service kembali
                        sshpass -p "$PASS" ssh -F /dev/null -p 27151 -o StrictHostKeyChecking=no $USER@163.52.135.170 \
                            "echo '$PASS' | sudo -S systemctl start agentGo"
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