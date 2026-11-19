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
                sh '''
                    COMMIT_INFO=$(git log -1 --pretty=format:"[%h] %s (%an)" 2>/dev/null || echo "Build #${BUILD_NUMBER}")
                    go run scripts/gather_notify.go -state "working" -msg "🔨 [BUILD #${BUILD_NUMBER}] Mulai: ${COMMIT_INFO}" || true
                '''
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
                echo '===> Mengirim binary ke cluster armada agent (Prod-1 s.d. Prod-7)...'
                withCredentials([
                    // 1. Prod-1 & Prod-2 (Kredensial Lama: vps-password)
                    usernamePassword(credentialsId: 'vps-password', usernameVariable: 'PROD12_USER', passwordVariable: 'PROD12_PASS'),
                    string(credentialsId: 'PROD-1-HOST', variable: 'PROD_1_HOST'),
                    string(credentialsId: 'PROD-1-PORT', variable: 'PROD_1_PORT'),
                    string(credentialsId: 'PROD-2-HOST', variable: 'PROD_2_HOST'),
                    string(credentialsId: 'PROD-2-PORT', variable: 'PROD_2_PORT'),

                    // 2. Prod-3 (Kredensial: VPS-AMANE)
                    usernamePassword(credentialsId: 'VPS-AMANE', usernameVariable: 'PROD3_USER', passwordVariable: 'PROD3_PASS'),
                    string(credentialsId: 'PROD-3-HOST', variable: 'PROD_3_HOST'),

                    // 3. Prod-4 s.d. Prod-7 (Kredensial: VPS-TOKOPUTRA)
                    usernamePassword(credentialsId: 'VPS-TOKOPUTRA', usernameVariable: 'PROD47_USER', passwordVariable: 'PROD47_PASS'),
                    string(credentialsId: 'PROD-4-HOST', variable: 'PROD_4_HOST'),
                    string(credentialsId: 'PROD-5-HOST', variable: 'PROD_5_HOST'),
                    string(credentialsId: 'PROD-6-HOST', variable: 'PROD_6_HOST'),
                    string(credentialsId: 'PROD-7-HOST', variable: 'PROD_7_HOST')
                ]) {
                    sh '''
                        set +x

                        cd Agent

                        deploy_to_root() {
                            local TARGET_HOST="$1"
                            local TARGET_PORT="$2"
                            local TARGET_PASS="$3"

                            echo "===> [DEPLOY] Mengirim agent ke root@$TARGET_HOST:$TARGET_PORT..."
                            
                            # Step A: Stop service & siapkan folder config
                            sshpass -p "$TARGET_PASS" ssh -F /dev/null -p "$TARGET_PORT" -o StrictHostKeyChecking=no -o ConnectTimeout=15 root@"$TARGET_HOST" \
                                "mkdir -p /root/Agent/config && (systemctl stop AgentGo || systemctl stop agentGo || true)"
                            
                            # Step B: Copy binary & file konfigurasi
                            sshpass -p "$TARGET_PASS" scp -F /dev/null -P "$TARGET_PORT" -o StrictHostKeyChecking=no \
                                AgentServerOnline root@"$TARGET_HOST":/root/Agent/
                            sshpass -p "$TARGET_PASS" scp -F /dev/null -P "$TARGET_PORT" -o StrictHostKeyChecking=no \
                                config/log_collector.json root@"$TARGET_HOST":/root/Agent/config/
                            
                            # Step C: Set permission & start service kembali
                            sshpass -p "$TARGET_PASS" ssh -F /dev/null -p "$TARGET_PORT" -o StrictHostKeyChecking=no root@"$TARGET_HOST" \
                                "chmod +x /root/Agent/AgentServerOnline && (systemctl start AgentGo || systemctl start agentGo)"
                            
                            echo "===> [OK] Selesai deploy ke root@$TARGET_HOST"
                        }

                        deploy_to_root "$PROD_1_HOST" "$PROD_1_PORT" "$PROD12_PASS"

                        echo "===> [DEPLOY] Mengirim agent ke $PROD12_USER@$PROD_2_HOST:$PROD_2_PORT..."
                        sshpass -p "$PROD12_PASS" ssh -F /dev/null -p "$PROD_2_PORT" -o StrictHostKeyChecking=no -o ConnectTimeout=15 $PROD12_USER@"$PROD_2_HOST" \
                            "mkdir -p /home/ubuntu/project/config && echo '$PROD12_PASS' | sudo -S systemctl stop agentGo"

                        sshpass -p "$PROD12_PASS" scp -F /dev/null -P "$PROD_2_PORT" -o StrictHostKeyChecking=no \
                            AgentServerOnline $PROD12_USER@"$PROD_2_HOST":/home/ubuntu/project/
                        sshpass -p "$PROD12_PASS" scp -F /dev/null -P "$PROD_2_PORT" -o StrictHostKeyChecking=no \
                            config/log_collector.json $PROD12_USER@"$PROD_2_HOST":/home/ubuntu/project/config/
                        sshpass -p "$PROD12_PASS" ssh -F /dev/null -p "$PROD_2_PORT" -o StrictHostKeyChecking=no $PROD12_USER@"$PROD_2_HOST" \
                            "chmod +x /home/ubuntu/project/AgentServerOnline && echo '$PROD12_PASS' | sudo -S systemctl start agentGo"
                        echo "===> [OK] Selesai deploy ke $PROD12_USER@$PROD_2_HOST"

                        deploy_to_root "$PROD_3_HOST" "22" "$PROD3_PASS"

                        for TARGET in "$PROD_4_HOST" "$PROD_5_HOST" "$PROD_6_HOST" "$PROD_7_HOST"; do
                            if [ -n "$TARGET" ]; then
                                deploy_to_root "$TARGET" "22" "$PROD47_PASS"
                            fi
                        done
                    '''
                }
            }
        }
    }

    post {
        success {
            echo "Build & deploy berhasil"
            sh '''
                COMMIT_INFO=$(git log -1 --pretty=format:"[%h] %s (%an)" 2>/dev/null || echo "Build #${BUILD_NUMBER}")
                go run scripts/gather_notify.go -state "on" -msg "🚀 [DEPLOY SUCCESS #${BUILD_NUMBER}] ${COMMIT_INFO}" -url "https://gowaz.vulnstack.xyz/analytics" || true
            '''
        }
        failure {
            echo "Pipeline gagal, coba di cek kembali"
            sh '''
                COMMIT_INFO=$(git log -1 --pretty=format:"[%h] %s (%an)" 2>/dev/null || echo "Build #${BUILD_NUMBER}")
                go run scripts/gather_notify.go -state "alert" -msg "❌ [BUILD FAILED #${BUILD_NUMBER}] ${COMMIT_INFO}" -url "https://gowaz.vulnstack.xyz/analytics" || true
            '''
        }
        always {
            echo "Pembersihan workspace selesai"
        }
    }
}