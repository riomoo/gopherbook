user="$(gpg2 -qd /home/moo/.local/pdf-keys/userkey)"
mkdir -p out
./cbt.sh create -i $1 -o ./out/$1.cbt -p $user
