<?php
namespace Pyncer\Snyppet\Access\Component\Module\User\Recovery;

use DateInterval;
use Psr\Http\Message\ResponseInterface as PsrResponseInterface;
use Pyncer\App\Identifier as ID;
use Pyncer\Component\Module\AbstractModule;
use Pyncer\Database\Exception\QueryException;
use Pyncer\Http\Message\JsonResponse;
use Pyncer\Http\Message\Status;
use Pyncer\Snyppet\Access\Table\User\UserModel;
use Pyncer\Snyppet\Access\Table\User\RecoveryMapper;
use Pyncer\Snyppet\Access\Table\User\RecoveryModel;
use Pyncer\Snyppet\Access\User\AccessManager;
use Pyncer\Snyppet\Access\User\LoginMethod;
use Pyncer\Validation\Rule\EmailRule;
use Pyncer\Validation\Rule\PhoneRule;
use Pyncer\Utility\Token;

use function Pyncer\code as pyncer_code;
use function Pyncer\date_time as pyncer_date_time;
use function Pyncer\String\nullify as pyncer_string_nullify;

use const Pyncer\DATE_TIME_FORMAT as PYNCER_DATE_TIME_FORMAT;
use const Pyncer\Snyppet\Access\LOGIN_METHOD as PYNCER_ACCESS_LOGIN_METHOD;
use const Pyncer\Snyppet\Access\RECOVERY_CODE_LENGTH as PYNCER_ACCESS_RECOVERY_CODE_LENGTH;
use const Pyncer\Snyppet\Access\RECOVERY_TOKEN_EXPIRATION as PYNCER_ACCESS_RECOVERY_TOKEN_EXPIRATION;
use const Pyncer\Snyppet\Access\USER_PHONE_ALLOW_E164 as PYNCER_ACCESS_USER_PHONE_ALLOW_E164;
use const Pyncer\Snyppet\Access\USER_PHONE_ALLOW_NANP as PYNCER_ACCESS_USER_PHONE_ALLOW_NANP;
use const Pyncer\Snyppet\Access\USER_PHONE_ALLOW_FORMATTING as PYNCER_ACCESS_USER_PHONE_ALLOW_FORMATTING;
use const Pyncer\Snyppet\Access\VALIDATE_LOGIN_NOT_FOUND as PYNCER_ACCESS_VALIDATE_LOGIN_NOT_FOUND;
use const Pyncer\Snyppet\Access\VALIDATE_CONTACT_MISMATCH as PYNCER_ACCESS_VALIDATE_CONTACT_MISMATCH;

abstract class AbstractPostRecoveryItemModule extends AbstractModule
{
    protected ?LoginMethod $loginMethod = null;
    protected ?int $recoveryCodeLength = null;
    protected ?int $recoveryTokenExpiration = null;
    protected ?bool $validateLoginNotFound = null;
    protected ?bool $validateContactMismatch = null;

    public function getLoginMethod(): LoginMethod
    {
        if ($this->loginMethod !== null) {
            return $this->loginMethod;
        }

        $loginMethod = PYNCER_ACCESS_LOGIN_METHOD;

        $snyppetManager = $this->get(ID::SNYPPET);
        if ($snyppetManager->has('config')) {
            $config = $this->get(ID::config());

            $loginMethod = $config->getString(
                'user_login_method',
                $loginMethod->value
            );
            $loginMethod = LoginMethod::from($loginMethod);
        }

        return $loginMethod;
    }
    public function setLoginMethod(?LoginMethod $value): static
    {
        $this->loginMethod = $value;

        return $this;
    }

    public function getRecoveryCodeLength(): int
    {
        if ($this->recoveryCodeLength !== null) {
            return $this->recoveryCodeLength;
        }

        $recoveryCodeLength = PYNCER_ACCESS_RECOVERY_CODE_LENGTH;

        $snyppetManager = $this->get(ID::SNYPPET);
        if ($snyppetManager->has('config')) {
            $config = $this->get(ID::config());

            $recoveryCodeLength = $config->getInt(
                'recovery_code_length',
                $recoveryCodeLength
            );
        }

        return $recoveryCodeLength;
    }
    public function setRecoveryCodeLength(?int $value): static
    {
        $this->recoveryCodeLength = $value;
        return $this;
    }

    public function getRecoveryTokenExpiration(): int
    {
        if ($this->recoveryTokenExpiration !== null) {
            return $this->recoveryTokenExpiration;
        }

        $recoveryTokenExpiration = PYNCER_ACCESS_RECOVERY_TOKEN_EXPIRATION;

        $snyppetManager = $this->get(ID::SNYPPET);
        if ($snyppetManager->has('config')) {
            $config = $this->get(ID::config());

            $recoveryTokenExpiration = $config->getInt(
                'recovery_token_expiration',
                $recoveryTokenExpiration
            );
        }

        return $recoveryTokenExpiration;
    }
    public function setRecoveryTokenExpiration(?int $value): static
    {
        $this->recoveryTokenExpiration = $value;
        return $this;
    }

    public function getValidateLoginNotFound(): bool
    {
        if ($this->validateLoginNotFound !== null) {
            return $this->validateLoginNotFound;
        }

        $validateLoginNotFound = PYNCER_ACCESS_VALIDATE_LOGIN_NOT_FOUND;

        $snyppetManager = $this->get(ID::SNYPPET);
        if ($snyppetManager->has('config')) {
            $config = $this->get(ID::config());

            $validateLoginNotFound = $config->getInt(
                'user_validate_login_not_found',
                $validateLoginNotFound
            );
        }

        return $validateLoginNotFound;
    }
    public function setValidateLoginNotFound(?bool $value): static
    {
        $this->validateLoginNotFound = $value;
        return $this;
    }

    public function getValidateContactMismatch(): bool
    {
        if ($this->validateContactMismatch !== null) {
            return $this->validateContactMismatch;
        }

        $validateContactMismatch = PYNCER_ACCESS_VALIDATE_CONTACT_MISMATCH;

        $snyppetManager = $this->get(ID::SNYPPET);
        if ($snyppetManager->has('config')) {
            $config = $this->get(ID::config());

            $validateContactMismatch = $config->getInt(
                'recovery_validate_contact_mismatch',
                $validateContactMismatch
            );
        }

        return $validateContactMismatch;
    }
    public function setValidateContactMismatch(?bool $value): static
    {
        $this->validateContactMismatch = $value;
        return $this;
    }

    protected function forgeAccessManager(): AccessManager
    {
        $connection = $this->get(ID::DATABASE);
        return new AccessManager($connection);
    }

    protected function getPrimaryResponse(): PsrResponseInterface
    {
        $connection = $this->get(ID::DATABASE);

        $accessManager = $this->forgeAccessManager();

        $loginMethod = $this->getLoginMethod();

        $loginMethod = $this->getLoginMethod();
        $loginValue = $this->parsedBody->getString($loginMethod->value);

        $errors = [];

        if ($loginValue === '') {
            $errors = [$loginMethod->value => 'required'];
            $userModel = null;
        } else {
            $accessManager = $this->forgeAccessManager();

            $userModel = $accessManager->getUserFromLogin(
                $loginValue,
                $loginMethod
            );

            if (!$userModel && $this->getValidateLoginNotFound()) {
                $errors = [$loginMethod->value => 'not_found'];
            }
        }

        if ($loginMethod === LoginMethod::USERNAME) {
            $email = $this->parsedBody->getString('email', null);
            $phone = $this->parsedBody->getString('phone', null);
        } elseif ($loginMethod === LoginMethod::EMAIL) {
            $email = $userModel?->getEmail();
            $phone = null;
        } elseif ($loginMethod === LoginMethod::PHONE) {
            $email = null;
            $phone = $userModel?->getPhone();
        }

        [$email, $phone, $contactErrors] = $this->validateUsernameContact(
            $userModel,
            $email,
            $phone,
        );

        // If only one contact method, use that method as error key instead of contact
        if ($loginMethod === LoginMethod::EMAIL || $loginMethod === LoginMethod::PHONE) {
            if (array_key_exists('contact', $contactErrors)) {
                if (!array_key_exists($loginMethod->value, $contactErrors)) {
                    $contactErrors[$loginMethod->value] = $contactErrors['contact'];
                }

                unset($contactErrors['contact']);
            }
        }

        $errors = array_merge($errors, $contactErrors);

        if (!$this->getValidateContactMismatch()) {
            if (($errors['phone'] ?? null) === 'mismatch') {
                unset($errors['phone']);
            }

            if (($errors['email'] ?? null) === 'mismatch') {
                unset($errors['email']);
            }
        }

        if ($errors) {
            return new JsonResponse(
                Status::CLIENT_ERROR_422_UNPROCESSABLE_ENTITY,
                [
                    'errors' => $errors
                ]
            );
        }

        $expirationDateTime = pyncer_date_time();
        $expirationDateTime->add(new DateInterval('PT' . $this->getRecoveryTokenExpiration() . 'S'));

        // If there is no user model or email and phone then validate login
        // not found is off so fake a successful request
        if ($userModel === null || ($email === null && $phone === null)) {
            return new JsonResponse(
                Status::SUCCESS_201_CREATED,
                [
                    'token' => strval(new Token()),
                    'expiration_date_time' => $expirationDateTime->format(PYNCER_DATE_TIME_FORMAT),
                ]
            );
        }

        try {
            $recoveryMapper = new RecoveryMapper($connection);
            $recoveryModel = new RecoveryModel([
                'user_id' => $userModel->getId(),
            ]);
            $recoveryMapper->insert($recoveryModel);
        } catch (QueryException) {
            $errors['general'] = 'insert';
        }

        if ($errors) {
            return new JsonResponse(
                Status::CLIENT_ERROR_422_UNPROCESSABLE_ENTITY,
                [
                    'errors' => $errors
                ]
            );
        }

        if (!$this->sendRecoveryCode($recoveryModel, $userModel, $email, $phone)) {
            $errors = ['general' => 'send'];

            return new JsonResponse(
                Status::CLIENT_ERROR_422_UNPROCESSABLE_ENTITY,
                [
                    'errors' => $errors
                ]
            );
        }

        $expirationDateTime = $recoveryModel->getExpirationDateTime()
            ->format(PYNCER_DATE_TIME_FORMAT);

        return new JsonResponse(
            Status::SUCCESS_201_CREATED,
            [
                'token' => $recoveryModel->getToken(),
                'expiration_date_time' => $expirationDateTime,
            ]
        );
    }

    protected function validateUsernameContact(
        ?UserModel $userModel,
        ?string $email,
        ?string $phone
    ): array
    {
        $errors = [];

        if ($phone === null && $email === null) {
            $errors = [
                'contact' => 'required',
            ];
        } elseif ($userModel &&
            $userModel->getPhone() === null &&
            $userModel->getEmail() === null
        ) {
            $errors = [
                'contact' => 'empty',
            ];
        }

        if ($phone !== null) {
            $phoneRule = new PhoneRule(
                allowNanp: PYNCER_ACCESS_USER_PHONE_ALLOW_NANP,
                allowE164: PYNCER_ACCESS_USER_PHONE_ALLOW_E164,
                allowFormatting: PYNCER_ACCESS_USER_PHONE_ALLOW_FORMATTING,
            );

            if (!$phoneRule->isValid($phone)) {
                $errors['phone'] = 'invalid';
            } elseif ($userModel) {
                $phone = $phoneRule->clean($phone);
                $phoneMatch = $phoneRule->clean($userModel->getPhone());

                if ($phone !== $phoneMatch) {
                    $error['phone'] = 'mismatch';
                    $phone = null;
                }
            }
        }

        if ($email !== null) {
            $emailRule = new EmailRule();

            if (!$emailRule->isValid($email)) {
                $errors['email'] = 'invalid';
            } elseif ($userModel) {
                $email = $emailRule->clean($email);
                $emailMatch = $emailRule->clean($userModel->getEmail());

                if ($email !== $emailMatch) {
                    $error['email'] = 'mismatch';
                    $email = null;
                }
            }
        }

        if ($userModel) {
            if ($userModel->getEmail() === null) {
                $email = null;
            }

            if ($userModel->getPhone() === null) {
                $phone = null;
            }
        } else {
            $email = null;
            $phone = null;
        }

        return [$email, $phone, $errors];
    }

    abstract protected function sendRecoveryCode(
        RecoveryModel $recoveryModel,
        UserModel $userModel,
        ?string $email,
        ?string $phone,
    ): bool;
}
