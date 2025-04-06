# Simulador de Tráfego de Rede
Ferramente auxiliar de simulação de tráfego de rede para o projeto de iniciação científica de [análise de desempenho de técnicas de aprendizado de máquina na classificação online de tráfego malicioso](https://bv.fapesp.br/pt/bolsas/213080/analise-de-desempenho-de-tecnicas-de-aprendizado-de-maquina-na-classificacao-online-de-trafego-malic/).

O sistema proposto é voltado para a geração de tráfego benigno e de ataque entre várias máquinas em uma rede. Esse tráfego será capturado e posteriormente convertido para um arquivo CSV a ser usado como entrada para IDSs. Uma das máquinas da rede, chamada de **Controlador** envia instruções para outras máquinas na rede realizarem troca de tráfego entre si. Cada uma dessas outras máquinas é chamada de **Operário**.

<p align="center">
  <img src="https://imgur.com/mqGKgfW.png" width="800">
</p>

## Como executar no Docker
Execute o controlador na máquina que quiser utilizar para fazer a captura (por ela deve passar o fluxo de rede dos operários):

```bash
docker run -it --network="host" --cap-add=NET_RAW --cap-add=NET_ADMIN -v .:/home milas098/network-test-controller <N_DE_OPERARIOS>
```

O parâmetro `-v` indica onde será montada a pasta /home do container no host do controlador, no exemplo acima, ele monta na pasta atual (`.`), porém isso pode ser modificado para o diretório que preferir.
Nesse diretório será criado o arquivo de configuração de features e a saída em CSV.

Os operários são executados na mesma rede, indicando o endereço do controlador:

```bash
docker run -it --network="host" milas098/network-test-node <IP_DO_CONTROLADOR>
```

Quando os operários forem iniciados e o controlador encontrar o número determinado de operários, um menu será apresentado no controlador para selecionar qual teste deseja executar, ou se deseja [modificar as features fixas nos testes](#modificando-as-features).

## Criando a imagem Docker localmente
Caso deseje criar sua própria imagem a partido do código fonte, basta clonar o repositório e utilizar o seguinte comando nas pastas do controlador e operário:
```bash
make
```
Além de criar a imagem, isso executará um [comandos de execução](#como-executar-no-docker) que inicia o operário com ip do `localhost` ou o controlador para 3 operários.

## Modificando as features
Quando o controlador for executado pela primeira vez, ele criará um arquivo `features.csv` contendo todas as features que o programa é capaz de extrair da captura de pacotes.
Cada linha do CSV contêm uma feature, seu valor padrão, seu nome no cabeçalho do arquivo de saída, e uma flag booleana que indica se ela está fixada.
Essas linhas também indicam a ordem que as features serão impressas no arquivo de saída.

Quando o arquivo é modificado, você deve utilizar a opção de recarregar as features no menu principal para que elas sejam atualizadas na memória. Nessa mesma opção, é possível (pela própria interface) fixar ou desfixar features na lista.

### Features fixas
Quando uma feature é fixa, o programa irá ignorar o valor que será obtido para ela na captura, inserindo o valor padrão dela (indicado no arquivo `features.csv`) em cada linha do CSV de saída.

### Features customizadas
É possível adicionar features que não fazem parte do conjunto que o programa consegue extrair da captura. Nesse caso, fixada ou não, seu valor padrão indicado será utilizado para preencher seu valor em cada linha da saída.
